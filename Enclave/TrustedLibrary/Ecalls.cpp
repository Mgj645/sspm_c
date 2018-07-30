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
#include "../Enclave.h"
#include "Enclave_t.h"

using namespace std;
map<string, string> DBPW;
int DBPW_len;
unsigned char key_[crypto_auth_hmacsha256_KEYBYTES];
unsigned char nonce[crypto_secretbox_NONCEBYTES];
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
    DBPW_len += countBytes;
    result[countBytes] = ' ';
    return result;
}

vector<vector<string>> ByteAtoVAA( char* byteA){
    vector<vector<string>> result;
    int i = 0;
    while(byteA[i] != ' ') {
        vector<string> toAdd;
        char op = byteA [i];
        toAdd.push_back(string(1,op));
        i+=2;
        string a = "";
        for(int j = i; byteA [j] != '^'; j++, i++ )
            a += byteA[j];

        toAdd.push_back(a); i++;
        a = "";
        for(int j = i; byteA [j] != '^'; j++, i++ )
            a += byteA[j];

        toAdd.push_back(a); i++;
        a= "";
        if(op == '1' || op == '2') {
            for (int j = i; byteA[j] != '~'; j++, i++)
                a += byteA[j];
            toAdd.push_back(a); i++;
        }
        i++;
        result.push_back(toAdd);
    }
    return result;
}


const int noUsers = 5;


//E-call used by condifion_variable demo - loader thread
void ecall_init()
{
    DBPW_len = 0;
    printf("hello world\n");
}

void ecall_encLOG(char *log, size_t len) {
    //turn back to vector<vector<string>> and put it to the unciphered database map string database
    int i = 0;
    while (log[i] != ' ' && i < len) {
        vector<string> toAdd;
        char op = log[i];
        toAdd.push_back(string(1, op));
        i += 2;
        string a;
        while( log[i] != '^')
            a += log[i++];

        toAdd.push_back(a);
        i++;
        a="";

        while( log[i] != '^')
            a += log[i++];

        toAdd.push_back(a);
        i++;
        a = "";
        if (op == '1' || op == '2') {
            for (int j = i; log[j] != '~'; j++, i++)
                a += log[j];
            toAdd.push_back(a);
            i++;
            DBPW.erase(toAdd[1]);
            DBPW.insert(pair<string, string>(toAdd[1], toAdd[3]));
        }
        else
            if(op == '0')
                DBPW.insert(pair<string, string>(toAdd[1], toAdd[2]));
            else
                DBPW.erase(toAdd[1]);
        i++;
    }

    //now turn it to char array before encryptying it back
    const unsigned char *result = reinterpret_cast<const unsigned char *>(MAPtoByteA(DBPW));


    //now to encrypt it
    unsigned char out[crypto_secretbox_MACBYTES + DBPW_len];
    printf("Encrypted\n");

    crypto_secretbox_easy(out, result, DBPW_len, nonce, key_);
   /* for(int i = 0; i < crypto_secretbox_MACBYTES + no; i++)
        printf("%c", out[i]);
    printf("\n");*/


   ocall_save_dbpw(reinterpret_cast<const char *>(out));

    //Decryption
   unsigned char in_d[DBPW_len];

    crypto_secretbox_open_easy(in_d, out, crypto_secretbox_MACBYTES+DBPW_len, nonce, key_);
    /* for(int i = 0; i < no; i++)
         printf("%c", in_d[i]);
     printf("\n");
 */
}



