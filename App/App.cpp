/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unordered_set>
#include <unistd.h>
#include <pwd.h>
#include <array>
#include <unordered_set>
#include <random>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <bits/stdc++.h>
#include <string.h>
#include <thread>
#include <mutex>
#include <sodium.h>
#include <fstream>

# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "App.h"
#include "Enclave_u.h"
using namespace std;
using namespace std;

unordered_set<string> users;
unordered_set<string> usernames;

vector<vector<string>> logV2;
mutex logTEX;
const int dumpTIME = 3;
int VC;
unsigned char key_[crypto_auth_hmacsha256_KEYBYTES];
unsigned char nonce[crypto_secretbox_NONCEBYTES];
string sep, sep2;
int no;
bool checkLogin = 0;
/*                      *
 *                      *
 *                      *
 *    INTEL SGX PART    *
 *                      *
 *                      *
 * */

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void) {
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;

    if (home_dir != NULL &&
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num
 = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

char * encDBPW;

void ocall_save_dbpw(const char * str) {
    encDBPW = const_cast<char *>(str);
    ofstream myfile;
    myfile.open("DBPW.txt");
    myfile << str;
    myfile.close();
}

void testlogin();

void ocall_save_users(const char *  users_) {




  int i = 0;
    while(users_[i] != '\0') {
        i++;
    }

   // cout << "got " << i << " " << users_ << endl;

    string r = "";

    users.clear();
    //cout << "users size" << users.size() << endl;

    i = 0;
    int k = 0;
    while(users_[i*8+1] != '\0') {
        for(int j = 0; j < 8 ; j++ )
            r+=users_[j+(i*8)];
        i++;
        users.insert(r);
        cout << r << endl;
        r="";
    }
    //cout << "users size" << users.size() << endl;


        checkLogin = 1;
}


/*                      *
 *                      *
 *                      *
 *     SSPM VERSIONS    *
 *                      *
 *                      *
 * */

//
// Created by miguel on 17-07-.2018
//


char * check_hmac_sgx(int code, string username, string password){

    int len = username.length() + password.length() + sep.length() ;
    string a; a.append(username); a.append(sep); a.append(password);
   // cout << "APP LOGIN input: " << a <<  " len: " << len << endl;

    char ** result = static_cast<char **>(malloc(len));
    ecall_hmac_this(global_eid, result, code, const_cast<char *>(a.c_str()), len);

    return *result;
}


bool RegisterV0(string username, string password){
    if (users.find(check_hmac_sgx(0, username, password)) == users.end()){
        users.insert(check_hmac_sgx(1, username, password));
        return true;
    }
    else{
        return false;
    }
}

bool changePasswordV0(string username, string password1, string password2){
    if (users.find(check_hmac_sgx(0, username, password1)) == users.end()){
        return false;
    }
    else{
        users.erase(check_hmac_sgx(2, username, password1));
        users.insert(check_hmac_sgx(1, username, password2));
        return true;
    }
}

bool changeUsernameV0(string username1, string password, string username2){
    if (users.find(check_hmac_sgx(0, username1, password)) == users.end()){
        return false;
    }
    else{
        users.erase(check_hmac_sgx(2, username1, password));
        users.insert(check_hmac_sgx(1, username2, password));
        return true;
    }
}

bool deleteUserV0(string username, string password){
    if (users.find(check_hmac_sgx(0, username, password)) == users.end()){
        return false;
    }
    else{
        users.erase(check_hmac_sgx(2, username, password));
        return true;
    }
}

bool RegisterV1(string username, string password){
    if (usernames.find(username) == usernames.end()){
        usernames.insert(username);
        users.insert(check_hmac_sgx(1, username, password));
        return true;
    }
    else{
        return false;
    }
}

bool changePasswordV1(string username, string password1, string password2){
    if (users.find(check_hmac_sgx(0, username, password1)) == users.end()){
        return false;
    }
    else{
        users.erase(check_hmac_sgx(2, username, password1));
        users.insert(check_hmac_sgx(1, username, password2));
        return true;
    }
}

bool changeUsernameV1(string username1, string password, string username2){
    if (users.find(check_hmac_sgx(0, username1, password)) == users.end()){
        return false;
    }
    else{
        usernames.erase(username1);
        usernames.insert(username2);
        users.erase(check_hmac_sgx(2, username1, password));
        users.insert(check_hmac_sgx(1, username2, password));
        return true;
    }
}

bool deleteUserV1(string username, string password){
    if (users.find(check_hmac_sgx(0, username, password)) == users.end()){
        return false;
    }
    else{
        users.erase(check_hmac_sgx(2, username, password));
        usernames.erase(username);

        return true;
    }
}

bool RegisterV2(string username, string password){
    if (usernames.find(username) == usernames.end()){
        usernames.insert(username);
        users.insert(check_hmac_sgx(1, username, password));
        return true;
    }
    else{
        return false;
    }
}

bool changePasswordV2(string username, string password1, string password2){
    if (users.find(check_hmac_sgx(0, username, password1)) == users.end()){
        return false;
    }
    else{
        users.erase(check_hmac_sgx(2, username, password1));
        users.insert(check_hmac_sgx(1, username, password2));

        return true;
    }
}

bool changeUsernameV2(string username1, string password, string username2){
    if (users.find(check_hmac_sgx(0, username1, password)) == users.end()){
        return false;
    }
    else{
        usernames.erase(username1);
        usernames.insert(username2);
        users.erase(check_hmac_sgx(2, username1, password));
        users.insert(check_hmac_sgx(1, username2, password));

        return true;
    }
}

bool deleteUserV2(string username, string password){
    if (users.find(check_hmac_sgx(0, username, password)) == users.end()){
        return false;
    }
    else{
        users.erase(check_hmac_sgx(2, username, password));
        usernames.erase(username);
        return true;
    }
}


char* MAPtoByteA(map<string, string> m){
    int countBytes = 0;
    for( const auto& sm_pair : m ) {
        string entry =  sm_pair.first;
        string value = sm_pair.second;
        countBytes += entry.size() + value.size() + 2;
    }
    char *result = static_cast<char *>(malloc(countBytes + 1));

    int counter = 0;
    for( const auto& sm_pair : m ){
        string entry =  sm_pair.first;
        string value = sm_pair.second;
        const int totalSize = entry.size() + value.size() + 2;
        char *baites = static_cast<char *>(malloc(totalSize));
        for(int i = 0; i < entry.size() ; i ++)
            baites[i] = entry.at(i);

        baites[entry.size()] = '^';

        int j = 0;
        for(int i = entry.size() + 1 ; i < entry.size()+ 1 + value.size() ; i ++)
            baites[i] = value.at(j++);

        baites[ entry.size()+ 1 + value.size()] = '~';


        for(int i = 0; i < totalSize; i++)
            result[i+counter] = baites[i];

        counter += totalSize;
        free(baites);
    }
    result[countBytes] = ' ';
    return result;
}

void dumpLog() {
    while(2+2==4) {
        if(checkLogin)
            testlogin();
            ecall_encLOG(global_eid);
            ecall_newHMAC(global_eid);
        sleep(dumpTIME);
    }
}

bool Login(string username, string password) {

    char * result = check_hmac_sgx(0, username, password);
    //cout << "APP: " << result << endl;
    std::unordered_set<std::string>::const_iterator got = users.find (result);
    return !(got == users.end());
}

bool Register(string username, string password){
    switch(VC){
        case 0 : return RegisterV0(username, password); break;
        case 1 : return RegisterV1(username, password); break;
        case 2 : return RegisterV2(username, password); break;
        default: printf("fucc the zucc"); return false;
    }
}

bool changePassword(string username, string password1, string password2){
    switch(VC){
        case 0 : return changePasswordV0(username, password1, password2);
        case 1 : return changePasswordV1(username, password1, password2);
        case 2 : return changePasswordV2(username, password1, password2);
        default: printf("only need 1 more candy to evolve my imaginary, arbitary pokemon"); return false;
    }
}

bool changeUsername(string username1, string password, string username2){
    switch(VC){
        case 0 : return changeUsernameV0(username1, password, username2);
        case 1 : return changeUsernameV1(username1, password, username2);
        case 2 : return changeUsernameV2(username1, password, username2);
        default: printf("you have the right to remain violent and start wildin'"); return false;
    }
}

bool deleteUser(string username, string password){
    switch(VC){
        case 0 : return deleteUserV0(username, password);
        case 1 : return deleteUserV1(username, password);
        case 2 : return deleteUserV2(username, password);
        default: printf("if you dress up a cobra, it's still a cobra. but a pretty one at that."); return false;
    }
}

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <dialog.h>

const int noUsers = 4;

string logins[noUsers];
string passwords[noUsers];

void simulateUsers() {
    string lineUser, linePassword;
    ifstream myfileUsers ("usernames.txt");
    ifstream myfilePass ("passwords.txt");

    if (myfileUsers.is_open() && myfilePass.is_open())
    {
        int i = 0;
        while ( getline (myfileUsers,lineUser) && getline (myfilePass,linePassword) && i< noUsers)
        {
            logins[i] = lineUser;
            passwords[i] =  linePassword;
            i++;
        }
        myfileUsers.close();
        myfilePass.close();
    }
    else cout << "Unable to open file";
}


void testlogin() {
    checkLogin = 0;
    for(int i = 0; i < noUsers; i++) {
        cout << Login(logins[i], passwords[i]) << endl;
    }
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    sep = "%|00%";
    sep2 = "%|%";


    (void)(argc);
    (void)(argv);
    simulateUsers();
    VC = 2;

    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL)
        fprintf(stdout, "Current working dir: %s\n", cwd);
    else
        perror("getcwd() error");

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_init(global_eid);
    if (ret != SGX_SUCCESS){
        printf("fatal error\n");
        exit(1);
    }
    cout << "sgx initiated sucessfuly"<< endl;

    for(int i = 0; i < noUsers; i++) {
        Register(logins[i], passwords[i]);
        cout << Login(logins[i], passwords[i]) << endl;
 }

    if(VC>1) {
        thread t(dumpLog);
        t.join();
    }

    /* Destroy the enclave */

    sgx_destroy_enclave(global_eid);

    printf("Info: Cxx11DemoEnclave successfully returned.\n");

    return 0;
}

