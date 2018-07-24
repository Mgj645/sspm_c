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

#include "../Enclave.h"
#include "Enclave_t.h"

using namespace std;
map<string, string> DBPW;

//E-call used by condifion_variable demo - loader thread
void ecall_init()
{
    printf("hello world\n");
}

void ecall_encLOG(uint8_t *buffer, size_t len) {

    //turn back to vector<vector<string>> and put it to the unciphered database map string database
    int i = 0;
    while (buffer[i] != ' ' && i < static_cast<int>(len)) {
        vector<string> toAdd;
        char op = buffer[i];
        toAdd.push_back(string(1, op));
        i += 2;
        string a = "";
        for (int j = i; buffer[j] != '^'; j++, i++)
            a += (char) buffer[j];

        toAdd.push_back(a);
        i++;
        a = "";
        for (int j = i; buffer[j] != '^'; j++, i++)
            a += (char) buffer[j];

        toAdd.push_back(a);
        i++;
        a = "";
        if (op == '1' || op == '2') {
            for (int j = i; buffer[j] != '~'; j++, i++)
                a += (char) buffer[j];
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

    //put it into the unciphered database array byte database

    //cipher the database back, using AES

}



