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
# include <unistd.h>
# include <pwd.h>
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
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "App.h"
#include "Enclave_u.h"
using namespace std;


/*                      *
 *                      *
 *                      *
 *     INTEL SGX PART       *
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
    size_t write_num    //sspm_v0 *s0 = new sspm_v0();
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

/*                      *
 *                      *
 *                      *
 *     SSPM VERSIONS       *
 *                      *
 *                      *
 * */

//
// Created by miguel on 17-07-2018.
//

using namespace std;

unordered_set<string> users;
unordered_set<string> usernames;

string sep;
string sha1_key(16, '\0');
vector<vector<string>> logV2;
mutex logTEX;
const int dumpTIME = 3;
int VC;
int no;
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
void testAES(unsigned char * plaintext){

    /* A 256 bit key */
    unsigned char *key = static_cast<unsigned char *>(malloc(32));
    for(int i = 0; i < 32; i ++)
        key[i] = (char) rand()%128;

    /* A 128 bit IV */
    unsigned char *iv = static_cast<unsigned char *>(malloc(16));
    for(int i = 0; i < 16; i ++)
        key[i] = (char) rand()%128;
    unsigned char ciphertext[no];

    /* Buffer for the decrypted text **/
    unsigned char decryptedtext[no];
    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                              ciphertext);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
                                decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';
}
string applyFunction(string username, string password){
    string c = "";
    c.append(username);
    c.append(sep);
    c.append(password);

    return c;
}

bool RegisterV0(string username, string password){
    if (users.find(applyFunction(username, password)) == users.end()){
        users.insert(applyFunction(username, password));
        return true;
    }
    else{
        return false;
    }
}

bool changePasswordV0(string username, string password1, string password2){
    if (users.find(applyFunction(username, password1)) == users.end()){
        return false;
    }
    else{
        users.erase(applyFunction(username, password1));
        users.insert(applyFunction(username, password2));
        return true;
    }
}

bool changeUsernameV0(string username1, string password, string username2){
    if (users.find(applyFunction(username1, password)) == users.end()){
        return false;
    }
    else{
        users.erase(applyFunction(username1, password));
        users.insert(applyFunction(username2, password));
        return true;
    }
}

bool deleteUserV0(string username, string password){
    if (users.find(applyFunction(username, password)) == users.end()){
        return false;
    }
    else{
        users.erase(applyFunction(username, password));
        return true;
    }
}

bool RegisterV1(string username, string password){
    if (usernames.find(username) == usernames.end()){
        usernames.insert(username);
        users.insert(applyFunction(username, password));
        return true;
    }
    else{
        return false;
    }
}

bool changePasswordV1(string username, string password1, string password2){
    if (users.find(applyFunction(username, password1)) == users.end()){
        return false;
    }
    else{
        users.erase(applyFunction(username, password1));
        users.insert(applyFunction(username, password2));
        return true;
    }
}

bool changeUsernameV1(string username1, string password, string username2){
    if (users.find(applyFunction(username1, password)) == users.end()){
        return false;
    }
    else{
        usernames.erase(applyFunction(username1, password));
        usernames.insert(applyFunction(username2, password));
        users.erase(applyFunction(username1, password));
        users.insert(applyFunction(username2, password));
        return true;
    }
}

bool deleteUserV1(string username, string password){
    if (users.find(applyFunction(username, password)) == users.end()){
        return false;
    }
    else{
        users.erase(applyFunction(username, password));
        usernames.erase(applyFunction(username, password));

        return true;
    }
}

bool RegisterV2(string username, string password){
    if (usernames.find(username) == usernames.end()){
        usernames.insert(username);
        users.insert(applyFunction(username, password));
        vector<string> toAdd;
        toAdd.push_back("0"); toAdd.push_back(username); toAdd.push_back(password);
        logTEX.try_lock();
        logV2.push_back(toAdd);
        logTEX.unlock();
        return true;
    }
    else{
        return false;
    }
}

bool changePasswordV2(string username, string password1, string password2){
    if (users.find(applyFunction(username, password1)) == users.end()){
        return false;
    }
    else{
        users.erase(applyFunction(username, password1));
        users.insert(applyFunction(username, password2));

        vector<string> toAdd;
        toAdd.push_back("1"); toAdd.push_back(username); toAdd.push_back(password1); toAdd.push_back(password2);
        logTEX.try_lock();
        logV2.push_back(toAdd);
        logTEX.unlock();
        return true;
    }
}

bool changeUsernameV2(string username1, string password, string username2){
    if (users.find(applyFunction(username1, password)) == users.end()){
        return false;
    }
    else{
        usernames.erase(applyFunction(username1, password));
        usernames.insert(applyFunction(username2, password));
        users.erase(applyFunction(username1, password));
        users.insert(applyFunction(username2, password));

        vector<string> toAdd;
        toAdd.push_back("2"); toAdd.push_back(username1); toAdd.push_back(username2); toAdd.push_back(password);
        logTEX.try_lock();
        logV2.push_back(toAdd);
        logTEX.unlock();
        return true;
    }
}

bool deleteUserV2(string username, string password){
    if (users.find(applyFunction(username, password)) == users.end()){
        return false;
    }
    else{
        users.erase(applyFunction(username, password));
        usernames.erase(applyFunction(username, password));
        vector<string> toAdd;
        toAdd.push_back("3"); toAdd.push_back(username); toAdd.push_back(password);
        logTEX.try_lock();
        logV2.push_back(toAdd);
        logTEX.unlock();
        return true;
    }
}

uint8_t* VVStoByteA(vector<vector<string>> m){
    int countBytes = 0;
    for( int i = 0; i < m.size(); i++ ) {
            int n = m[i][0].at(0); //check how many strings does a entry have
            countBytes += 1 + 1;
            countBytes += m[i][1].size()+ 1;
            countBytes += m[i][2].size() + 1;
            if( n  == 1 || n == 2) {
                countBytes += m.size() + 1;
            }
            countBytes++;
        }
        no = countBytes;

    uint8_t *result = static_cast<uint8_t *>(malloc(countBytes + 1));
    int counter = 0;

    for( int i = 0; i < m.size(); i++ ) {
        int n = m[i][0].at(0); //check how many strings does a entry have
        result[counter++] = n; result[counter++] = '^';
            for(int j = 0; j < m[i][1].size() ; j ++)
                result[counter++] = (uint8_t) m[i][1].at(j);
            result[counter++] = '^';
            for(int j = 0; j < m[i][2].size() ; j ++)
                result[counter++] = (uint8_t) m[i][2].at(j);
                result[counter++] = '^';
            if( n  == 1 || n == 2) {
                string p_ = m[i][3];
                for(int j = 0; j < p_.size() ; j ++)
                    result[counter++] = (uint8_t) p_.at(j);
            }
        result[counter++] = '~';
    }
    result[counter] = ' ';
    no = countBytes + 1;
    return result;
}

vector<vector<string>> ByteAtoVAA( uint8_t* byteA){
    vector<vector<string>> result;
    int i = 0;
    while(byteA[i] != ' ') {
        vector<string> toAdd;
        char op = byteA [i];
        toAdd.push_back(string(1,op));
        i+=2;
        string a = "";
        for(int j = i; byteA [j] != '^'; j++, i++ )
            a += (char) byteA[j];

        toAdd.push_back(a); i++;
        a = "";
        for(int j = i; byteA [j] != '^'; j++, i++ )
            a += (char) byteA[j];

        toAdd.push_back(a); i++;
        a= "";
        if(op == '1' || op == '2') {
            for (int j = i; byteA[j] != '~'; j++, i++)
                a += (char) byteA[j];
            toAdd.push_back(a); i++;
        }
        i++;
        result.push_back(toAdd);
    }
    return result;
}


uint8_t* MAPtoByteA(map<string, string> m){

    int countBytes = 0;
    for( const auto& sm_pair : m ) {
        string entry =  sm_pair.first;
        string value = sm_pair.second;
        countBytes += entry.size() + value.size() + 2;
    }
    uint8_t *result = static_cast<uint8_t *>(malloc(countBytes + 1));


    int counter = 0;
    for( const auto& sm_pair : m ){
        string entry =  sm_pair.first;
        string value = sm_pair.second;
        const int totalSize = entry.size() + value.size() + 2;
        uint8_t *baites = static_cast<uint8_t *>(malloc(totalSize));
        for(int i = 0; i < entry.size() ; i ++)
            baites[i] = (uint8_t) entry.at(i);

        baites[entry.size()] = '^';

        int j = 0;
        for(int i = entry.size() + 1 ; i < entry.size()+ 1 + value.size() ; i ++)
            baites[i] = (uint8_t) value.at(j++);

        baites[ entry.size()+ 1 + value.size()] = '~';


        for(int i = 0; i < totalSize; i++)
            result[i+counter] = baites[i];

        counter += totalSize;
        free(baites);
    }
    result[countBytes] = ' ';
    return result;
}

map<string, string> ByteAtoMAP( uint8_t* byteA){
    map<string, string> result;
    string a= "";
    string b = "";
    bool aChecked = 0;

    for(int i = 0 ; byteA[i] != ' '; i++){
        uint8_t now = byteA[i];
        if(!aChecked)
            if (now == '^')
                aChecked = 1;
            else
                a += (char) now;
        else

        if (now == '~') {
            aChecked = 0;
            result.insert(pair<string, string>(a,b));
            a = ""; b = "";
        }
        else
            b += (char) now;

    }
    return result;


}
void dumpLog() {
    //map<string, string> DBPW;
    //DBPW = CipheredDB.deciphered

    while(2+2==4) {
        sleep(dumpTIME);
        if(logV2.size() > 0) {
            uint8_t *caites = VVStoByteA(logV2);
            sgx_status_t ret = SGX_ERROR_UNEXPECTED;
            ret = ecall_encLOG(global_eid, caites, no);
            if (ret != SGX_SUCCESS) {
                printf("fatal error\n");
                // exit(1);
            }

            vector<vector<string>> vaites = ByteAtoVAA(caites);
            // cout << "Log" << endl;
           /* logTEX.try_lock();
            for (int i = 0; i < logV2.size(); i++) {
                switch (logV2[i][0].at(0)) {
                    case '0' :
                        DBPW.insert(pair<string, string>(logV2[i][1], logV2[i][2]));
                        break;
                    case '1' :
                        DBPW.erase(logV2[i][1]);
                        DBPW.insert(pair<string, string>(logV2[i][1], logV2[i][3]));
                        break;
                    case '2' :
                        DBPW.erase(logV2[i][1]);
                        DBPW.insert(pair<string, string>(logV2[i][2], logV2[i][3]));
                        break;
                    case '3' :
                        DBPW.erase(logV2[i][1]);
                        break;
                    default :
                        cout << "Isto nao era suposto acontecer" << endl;
                        break;
                }
            }
            */
            /*teste*//*
            uint8_t *Baites = MAPtoByteA(DBPW);
            map<string, string> DBPW2 = ByteAtoMAP(Baites);
            */
            logV2.clear();
            logTEX.unlock();
        }
    }
    return ;
}

int sspm(const int version) {
    sep = "%|00%";
    std::random_device rd;
    std::mt19937_64 gen{std::random_device{}()};
    std::uniform_int_distribution<short> dist{'a', 'z'};

    for(auto& c: sha1_key)
        c = dist(gen);

    VC = version;

    if(VC > 1){
        thread t(dumpLog);
        t.join();
        cout << "Ended Initialization" << endl;
    }
    return 0;
}

bool Login(string username, string password) {
    return !(users.find(applyFunction(username, password)) == users.end());
}

bool Register(string username, string password){
    printf("register\n");

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

const int noUsers = 5;

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

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    simulateUsers();
    VC = 2;
    for(int i = 0; i < noUsers; i++) {
            Register(logins[i], passwords[i]);
            Login(logins[i], passwords[i]);
    }

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL)
        fprintf(stdout, "Current working dir: %s\n", cwd);
    else
        perror("getcwd() error");


    void* buf = malloc(2);
    ((char*)buf)[0] = '7';
    ((char*)buf)[1] = 'b';

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_init(global_eid);
    if (ret != SGX_SUCCESS){
        printf("fatal error\n");
        exit(1);
    }
    cout << "oi"<< endl;
    free(buf);

    /* Destroy the enclave */
    if(VC>1) {
        thread t(dumpLog);
        t.join();
    }

    sgx_destroy_enclave(global_eid);

    printf("Info: Cxx11DemoEnclave successfully returned.\n");

    return 0;
}

