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

#include <iostream>

#include <string>
#include <vector>
#include <iterator>
#include <typeinfo>
#include <functional>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <initializer_list>
#include <tuple>
#include <memory>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <map>
#include <vector>
#include <sodium.h>
#include <Enclave_t.h>
#include <random>
#include <cstring>
#include "../Enclave.h"
#include "Enclave_t.h"
#include <list>
#include "sgx_trts.h"

using namespace std;
map<string, string> decDBPW;
int DBPW_len;
unsigned char key_[crypto_auth_hmacsha256_KEYBYTES];
unsigned char nonce[crypto_secretbox_NONCEBYTES];
const char *sep, *sep2;
char * sha1_key;
//unordered_set<char *> users;
vector<vector<string>> logV2;

void gen_new_key(){
    sha1_key = static_cast<char *>(malloc(8));
    for(int i = 0; i < 8; i ++) {
        uint8_t val;
        sgx_read_rand((unsigned char *) &val, 1);
        val = val % 127;
        sha1_key[i] = (char) val;
    }
}


string applyFunction(char* username, char* password){
    string c, result = "";
    c.append(username);
    c.append(sep);
    c.append(password);
    int len = c.size();
    unsigned char out[len];
    unsigned char in[len];
    unsigned long long in_len = 8;
    for(int i = 0; i < len; i ++ )
        in[i] = (unsigned char) c.at(i);
    crypto_auth_hmacsha256(out, in, in_len, reinterpret_cast<const unsigned char *>(sha1_key));
    for(int i = 0; i < in_len ; i++)
        result+=out[i];
    return result;
}


char* MAPtoByteA(map<string, string> m){
    map<string, string>::iterator it = decDBPW.begin();

    int countBytes = 0;
    for (it=decDBPW.begin(); it!=decDBPW.end(); ++it){
        string entry =  it->first;
        string value = it->second;
        countBytes += entry.size() + value.size() + 2;
       // printf("pass %s \n", value.c_str());
    }
    char *result = static_cast<char *>(malloc(countBytes + 1));

    int counter = 0;
    it = m.begin();
    for (it=m.begin(); it!=m.end(); ++it){
        string entry =  it->first;
        string value = it->second;
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
    DBPW_len += countBytes;
    result[countBytes] = ' ';
    return result;
}


void ecall_encLOG() {
    map<string, string> dec;

    //turn back to vector<vector<string>> and put it to the unciphered database map string database
    int i = 0;
    for( int i = 0; i < logV2.size(); i++ ) {
      //  printf("logv2 %s: %s\n", logV2[i][1].c_str(), logV2[i][2].c_str());
        //char *

        char code = logV2[i][0][0];

        if(code == '1') {
            decDBPW.insert(pair<string, string>(logV2[i][1], logV2[i][2]));
           // printf("pass %s\n", logV2[i][2]);
        }

        if(code == '2') {
            decDBPW.erase(logV2[i][1]);
            printf("erade %s\n");

        }
    }
    logV2.clear();

   // map<string, string>::iterator it = decDBPW.begin();
   // for (it=decDBPW.begin(); it!=decDBPW.end(); ++it)
     //   printf( "%s  << << %s << '\n",it->first.c_str(), it->second.c_str() ) ;


    //now turn it to char array before encryptying it back
    const unsigned char *result = reinterpret_cast<const unsigned char *>(MAPtoByteA(decDBPW));


    //now to encrypt it
    unsigned char out[crypto_secretbox_MACBYTES + DBPW_len];
            sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    crypto_secretbox_easy(out, result, DBPW_len, nonce, key_);

   ocall_save_dbpw(reinterpret_cast<const char *>(out));

    //Decryption
   /*
    unsigned char in_d[DBPW_len];

    crypto_secretbox_open_easy(in_d, out, crypto_secretbox_MACBYTES+DBPW_len, nonce, key_);
    printf("ola\n");
     for(int i = 0; i < DBPW_len; i++)
         printf("%c", in_d[i]);
     printf("\n");
     */

}

void ecall_newHMAC(){
    gen_new_key();
    //users.clear();

    /*char * * r = static_cast<char **>(malloc(decDBPW.size()));
    for(int i = 0; i < decDBPW.size(); i++)
        r[i] = static_cast<char *>(malloc(8));*/
    //char * re = static_cast<char *>(malloc(decDBPW.size()));
    int k = 0;

    int elems = 0;
    vector<string> strings(decDBPW.size());
    map<string, string>::iterator it = decDBPW.begin();
    for (it=decDBPW.begin(); it!=decDBPW.end(); ++it){
        string entry = it->first;
        string value = it->second;
        string elem = applyFunction(const_cast<char *>(entry.c_str()), const_cast<char *>(value.c_str()));
        //printf("%s\n", elem);
        strings[elems++] = elem;
    }
    char re[decDBPW.size()*8];
    for(int i = 0; i < decDBPW.size(); i ++)
        for (int j = 0; j < 8; j++)
            re[(i*8)+j] = strings[i].at(j);

   // for(int i = 0; i < decDBPW.size(); i ++)
    //    printf("string: %s ||| re: %s\n", strings[i].c_str(), re);

    ocall_save_users(re);
}

char * ecall_hmac_this(int code, char *u, size_t len) {
    string aaa = string(u,len);

    int k = 0;
    u = const_cast<char *>(aaa.c_str());
    char *b = strtok(u, sep);
    char *a = b;
    printf("login0 %i:%s:%s\n", len, a,b);

    b = strtok(NULL, sep);

    if(code == 1){
        vector<string> toAdd;
        toAdd.push_back("1"); toAdd.push_back(a); toAdd.push_back(b);  logV2.push_back(toAdd);
    }

    if(code == 2){
        vector<string> toAdd;
        toAdd.push_back("2"); toAdd.push_back(a); toAdd.push_back(b);  logV2.push_back(toAdd);
    }
    printf("login1 %i:%s:%s\n", len, a,b);

    return const_cast<char *>(applyFunction(a, b).c_str());

}


//E-call used by condifion_variable demo - loader thread
void ecall_init(){
    sep = "%|00%";
    sep2 = "%|%";

    DBPW_len = 0;
    printf("hello enclave world\n");

    gen_new_key();
}



