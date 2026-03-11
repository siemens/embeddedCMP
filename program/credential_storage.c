/*
 *  Copyright (c) 2019 Siemens AG
 * *
 *  Licensed under the Apache License, Version 2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 * file_helpers.c
 *
 *  Created on: 22.11.2018
 *      Author: z0039e0m
 */

#include "credential_storage.h"

#include "cmpcl.h"
#include "debug_macros.h"
#include "mbedtls/pem.h"
#include <string.h>
#include <stdlib.h>
//#include <sys/stat.h>
#include <errno.h>
//#include <stdbool.h> // REQUIRED for 'bool', 'true', and 'false'

/* **************************************************************** */

#define MAX_FILE_SIZE 8000

#define CERTS_ROOT_PATH "./resources/certs/playground/"
#define PATH_TO_PROTECTION_CERT CERTS_ROOT_PATH "protection/CMP_EE_Cert.pem"
#define PATH_TO_PROTECTION_CHAIN CERTS_ROOT_PATH "protection/CMP_EE_Chain.pem"
#define PATH_TO_PROTECTION_KEY CERTS_ROOT_PATH "protection/CMP_EE_Key.pem"
#define PATH_TO_PROTECTION_TRUST_ANCHOR_PEM    CERTS_ROOT_PATH  "trusted/prot_ca.crt"
#define PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM    CERTS_ROOT_PATH  "trusted/enr_ca.crt"

#define TLS_CREDENTIAL_ROOT CERTS_ROOT_PATH "tlssrv/"
#define TLS_SERVER_ROOT TLS_CREDENTIAL_ROOT "srvcrt.crt"
#define TLS_CLIENT_KEY TLS_CREDENTIAL_ROOT "clientkey.key"
#define TLS_CLIENT_CERT TLS_CREDENTIAL_ROOT "clientcert.crt"

static unsigned char content_buffer[MAX_FILE_SIZE];

// Hardcoded certificate string
// Note: Backslashes are used to continue the string literal on new lines.
// The final '\n' after -----END CERTIFICATE----- is important for PEM format.

static const char * const HARDCODED_TLS_CLIENT_CERT =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIE4jCCAsqgAwIBAgIUZRLlQBZ6CCryLv6RcW4ij7vTGEYwDQYJKoZIhvcNAQEN\n"
    "BQAwgaIxNzA1BgNVBAMMLlBQS0kgUGxheWdyb3VuZCBJbmZyYXN0cnVjdHVyZSBJ\n"
    "c3N1aW5nIENBIHYyLjAxHjAcBgNVBAsMFUNvcnBvcmF0ZSAgVGVjaG5vbG9neTEo\n"
    "MCYGA1UECwwfRm9yIGludGVybmFsIHRlc3QgcHVycG9zZXMgb25seTEQMA4GA1UE\n"
    "CgwHU2llbWVuczELMAkGA1UEBhMCREUwHhcNMjUwNTIzMDk0ODE2WhcNMzAwNTIy\n"
    "MDk0ODE1WjCBrjEqMCgGA1UEAwwhUHJvZHVjdCBQS0kgUGxheWdyb3VuZCBUTFMg\n"
    "Q2xpZW50MRgwFgYDVQQLDA9QUEtJIFBsYXlncm91bmQxHTAbBgNVBAsMFENvcnBv\n"
    "cmF0ZSBUZWNobm9sb2d5MSgwJgYDVQQLDB9Gb3IgaW50ZXJuYWwgdGVzdCBwdXJw\n"
    "b3NlcyBvbmx5MRAwDgYDVQQKDAdTaWVtZW5zMQswCQYDVQQGEwJERTCBmzAQBgcq\n"
    "hkjOPQIBBgUrgQQAIwOBhgAEAcmYDeIEL4HczcWIy84t9+ZIVbrx+tdpWyGL5ZlQ\n"
    "iiDwX3RqB3fFWtnpcWGstcO1bnMkeLNx5nhKf4UMNGUv0UijAZizYEUKdbhklCc7\n"
    "OkOmNd+X11ab3OISvrug9LRaBBBNF5iC74zrBmV2nL+Kyj3wREyRB/ndsm4fOtcS\n"
    "kddB5Vzxo4GJMIGGMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUWf19JT+ri/nR\n"
    "8vP0ho8sJ3/AdLwwEQYDVR0gBAowCDAGBgRVHSAAMBMGA1UdJQQMMAoGCCsGAQUF\n"
    "BwMCMB0GA1UdDgQWBBSO5FZ9DnjCZZJlRPYIsASPjfFMVzAOBgNVHQ8BAf8EBAMC\n"
    "BeAwDQYJKoZIhvcNAQENBQADggIBAG/TwHlW+R5ifi4fh8N+k1ORBpp5aNsBGcmg\n"
    "2cxxr8KAfS9h9mkHF7iF7UILWGzl3pVER/KarclrAX6dFrRgm6Ptf8IunnAi7kNy\n"
    "dFzeWLzwTX1N4XnkrsNy/Y+I8shKNY5/cKNkAx5/+RZeTVad2lTeTCTy6r4sFTBV\n"
    "8DvN7zaiq3mMRYeLOFyuY4KGMDBX/hxODz+3ozlSp0hoAAdQgE8ncBo6XtigSFBb\n"
    "mpR1IaTbkxNZzranCQYnakOUvcflnawvja5+H7e2OwnZIMfTKWD49tWwj29noApf\n"
    "76kv1g7eh9uO6YYaC6HLC0x197SfXD30MBYk+aApXc0XeTQLoggJdDJYOE2uhALa\n"
    "x+Tcjxcnyk/E+GrtLZMPkygtGNwH8vTQZAnnzFMut1APmOTTxIxa3TsKMn0dbJvu\n"
    "FN4eYsanLbeoR1tLY4oXlFSt3sRXenqXFebJ+dMOTbj3k18q+5scyRZ/rnKzAmNl\n"
    "ukoOGfe8Rk0iIUj9kp6QOMg/VV1oS6Y0uaV3cuzc8GJnGFf5w2ulhxPJXUFMoe7I\n"
    "JnEtYkhxOoiCwagvG5EyThZtu6U+uvKfTjNee99Jrwzd+T6Z1Z+qg1ekAy819xKo\n"
    "qDoYLqecHArxc8gGuJ+eLcaDPoAfhmivIXXyorNgtaDAABXRi4zOtnmhb23eVxGr\n"
    "ErD55BlX\n"
    "-----END CERTIFICATE-----\n"; // Compiler implicitly adds final null terminator here.
    
static const char * const HARDCODED_TLS_CLIENT_KEY =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBtz0ajwX1cNNZydU9\n"
    "N7ZzSA+4j0IFm+DtXXAhDhiMyLDvnVTaey3J1qS8sdm6JIPf9YmDv1QlmbkWfUr0\n"
    "W/Pg1wehgYkDgYYABAHJmA3iBC+B3M3FiMvOLffmSFW68frXaVshi+WZUIog8F90\n"
    "agd3xVrZ6XFhrLXDtW5zJHizceZ4Sn+FDDRlL9FIowGYs2BFCnW4ZJQnOzpDpjXf\n"
    "l9dWm9ziEr67oPS0WgQQTReYgu+M6wZldpy/iso98ERMkQf53bJuHzrXEpHXQeVc\n"
    "8Q==\n"
    "-----END PRIVATE KEY-----\n"; // Compiler implicitly adds final null terminator here.

static const char * const HARDCODED_TLS_SERVER_ROOT =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIGMTCCBBmgAwIBAgIUde8puSB/m2J/olW0GdDLqA3QRLAwDQYJKoZIhvcNAQEN\n"
    "BQAwgZ4xNDAyBgNVBAMMK1BQS0kgUGxheWdyb3VuZCBJbmZyYXN0cnVjdHVyZSBS\n"
    "b290IENBIHYyLjAxHTAbBgNVBAsMFENvcnBvcmF0ZSBUZWNobm9sb2d5MSgwJgYD\n"
    "VQQLDB9Gb3IgaW50ZXJuYWwgdGVzdCBwdXJwb3NlcyBvbmx5MRAwDgYDVQQKDAdT\n"
    "aWVtZW5zMQswCQYDVQQGEwJERTAgFw0yNTA1MjIxNTQ4NTRaGA8yMDUwMDUxNjE1\n"
    "NDg1M1owgZ4xNDAyBgNVBAMMK1BQS0kgUGxheWdyb3VuZCBJbmZyYXN0cnVjdHVy\n"
    "ZSBSb290IENBIHYyLjAxHTAbBgNVBAsMFENvcnBvcmF0ZSBUZWNobm9sb2d5MSgw\n"
    "JgYDVQQLDB9Gb3IgaW50ZXJuYWwgdGVzdCBwdXJwb3NlcyBvbmx5MRAwDgYDVQQK\n"
    "DAdTaWVtZW5zMQswCQYDVQQGEwJERTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC\n"
    "AgoCggIBAIxoyV9mcP7wKEsEsIXKSSbM1r+7qwQzP5ccW3P5nWPo0gdTqx47kG5c\n"
    "74HcNjHOo0BnvDePs1S9z2LUknTi78jFSv6btLzZg9Kl7ye74yol2j+GmeMhhpmk\n"
    "ABZfRuk6DPAO66Pa/st+lX6aq1MWqPrjneRckTj+lZrl90Gt9Qwmp98FmgyaXYH5\n"
    "nTl3N4kiD+cBom6PBmU2aRnXJZTsz/kNXgIC+871UEmvksbeD+L5nmKbDLhgB/Iy\n"
    "77aNXPogHJe/17V6ofDq9Zrh7xWD9/Q7U93kdKKNnaVY8c8rooNjFUDnx6Kz+faA\n"
    "8S5rDYdOp4o5vzJbWIi62S+fw8crWhD9AjuunBwoZatMFYtGfWKflGkyg6M0htz9\n"
    "6YMMmvZ714suFTT18kNEihTkOqyhUaNhmI/gKVNdP3Mv6RWOavHbXAAxbMsG1GGE\n"
    "Mqw84vIYMul//UDuPtOteKZaARfNVIcNM+ol/xL2tsoDCWZGm3u/1vvIifU4uBa7\n"
    "gC3szG21dXp0JHIAURzEzcJVYu8VMyxF74nUZDFPh0609l3Bgkcs4uNwbmYy0jmN\n"
    "aEXOtj4LDtmdsFVGH6s506SlXY/0mf8Dxkb2/v2lesU/5DKnmAs38YKbky+ILphm\n"
    "i2JrajKBt0macb+qYvfd6vOTeqKeyba/yhwYfMCJ42sI34YXyPN/AgMBAAGjYzBh\n"
    "MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUT2MpM5TCa2jWbr1LzPEzHWLZ\n"
    "1nUwHQYDVR0OBBYEFE9jKTOUwmto1m69S8zxMx1i2dZ1MA4GA1UdDwEB/wQEAwIB\n"
    "hjANBgkqhkiG9w0BAQ0FAAOCAgEAUEAcpPNPyc38aAhHBujONrp/vcCVgZxCBf7I\n"
    "3jBt+lsSUbeC2kza/mu36cH8MLPouoJvVVDBrsJa9+co0pOY/L0XK8qQ7dfIr2Ox\n"
    "lS0JngSQ8SwGhX770OD4wUDhGhHTdRUpzXKwwV7E/YXRxqpMIDWCwF/Z3iiAGcf/\n"
    "Ed/+TEXrwcjaRPEdXoXqtHIQfFkn/HChJzGZOumg/I5y23RSmh3E/97nhW77sAFs\n"
    "WT+DoIUT9NPQXv6pNc2zqtmBzUIfxkmy8EIqqVabX6Fw/w43ADaoHWqBcBjZhWVA\n"
    "BagZKJXqJPbbb6xe1GQWW6Oq3w+tSsL+xeqc5OSjO6EndYzH6dRvhroO5TJWEDxA\n"
    "qv7qFnfJRysLWEBd2OzAAGYGXxTxjnIcOTg9/w5PwH28Cu1QazyP3DYMTL6NdFuE\n"
    "pfHxsAZxZRpPivR/xLqu5htbEuTnGPtLuGTYR+0zParCZSH0VD+N/F68l4kUMovQ\n"
    "oYPq+HXjLP+kF7D6N18HNJA/rGWzhBDp8AHiB+ZtBt4zaWQd7nvQSbwrqVT++lpc\n"
    "R9WDUFkUaYVzKiZKdMLonm7je2MkZbX6+evg6flP7E47CFRKdMEkdzS3Kdw+LzdA\n"
    "1J+h4YEYahG7u1to5uItgkjSrjMgiXBlfEMk2xSKObIfFfxOLrklMv0MKAdhShtV\n"
    "cli9ACs=\n"
    "-----END CERTIFICATE-----\n"; // Compiler implicitly adds final null terminator here.    

static const char * const HARDCODED_PROTECTION_CERT =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEyzCCArOgAwIBAgIUZJkCuqm5BkfFlTaNMIWpSRHQUD0wDQYJKoZIhvcNAQEN\n"
    "BQAwgaIxNzA1BgNVBAMMLlBQS0kgUGxheWdyb3VuZCBJbmZyYXN0cnVjdHVyZSBJ\n"
    "c3N1aW5nIENBIHYyLjAxHjAcBgNVBAsMFUNvcnBvcmF0ZSAgVGVjaG5vbG9neTEo\n"
    "MCYGA1UECwwfRm9yIGludGVybmFsIHRlc3QgcHVycG9zZXMgb25seTEQMA4GA1UE\n"
    "CgwHU2llbWVuczELMAkGA1UEBhMCREUwHhcNMjUwNTIzMTAyODUwWhcNMzAwNTIy\n"
    "MTAyODQ5WjCBrjEqMCgGA1UEAwwhUHJvZHVjdCBQS0kgUGxheWdyb3VuZCBDTVAg\n"
    "U2lnbmVyMRgwFgYDVQQLDA9QUEtJIFBsYXlncm91bmQxHTAbBgNVBAsMFENvcnBv\n"
    "cmF0ZSBUZWNobm9sb2d5MSgwJgYDVQQLDB9Gb3IgaW50ZXJuYWwgdGVzdCBwdXJw\n"
    "b3NlcyBvbmx5MRAwDgYDVQQKDAdTaWVtZW5zMQswCQYDVQQGEwJERTCBmzAQBgcq\n"
    "hkjOPQIBBgUrgQQAIwOBhgAEASx8dtaJJbIY/1Zy7wrQkweSPNxg4kq4vx3O7Up7\n"
    "H/h/wRO8xlLsx74/UUUNVQzhlcCia8wQS0a/a7hqm9qS20AuAKQgj4/1rLKC7E2c\n"
    "SVnC5lzywN8I750KFirzF7UTzJS2TIEmVFJ0l4GbmVIxRw6hyCAjCiRt8cvtUKGv\n"
    "Unwve0Kgo3MwcTAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFFn9fSU/q4v50fLz\n"
    "9IaPLCd/wHS8MBEGA1UdIAQKMAgwBgYEVR0gADAdBgNVHQ4EFgQUsqYFbNQW+QxR\n"
    "u6Rd+rlDBlWHpRwwDgYDVR0PAQH/BAQDAgXgMA0GCSqGSIb3DQEBDQUAA4ICAQBD\n"
    "YjKYifehtT2y1nRXi6IDHYP2EtHMABW5bZHufy4Sth0v2O7me24jYq/+ywdiDKpi\n"
    "IK4wxDmHPlKPn6y/6v7vVocbOrjod/hyaZlcl0hEfjq+SxrYUzYL36vR/CkLC1Al\n"
    "/Tkxhzl0Z7hk55WzbuLBjRRyBpEqj+LA4KHS/3jxuL7ac62LiP9JDWh8DI/r4PeA\n"
    "KRNjLLfVIbqBuRIT41x/jiitkdEwGeU1gmnqL2t0OCb128SLZKfdozvdmh16H738\n"
    "+YMZ5YImAhA3zJchAv4m3xyZhoX83FkqjF4M+WNP4am+qHgq5gModaMY6UsKtaQe\n"
    "h6zbvHM3nuKZqZtormdGfb6s4K/MvBXPegZwkyXRDTyrf2y0tVdU3ViZ1BbO5AYc\n"
    "N+2MunAtHqX8lLjrcJYAlRDJINjDP/m6S/uHRi2Ilpxi9k+g82i+3s4BUONXcyve\n"
    "oka3LspcAslZ6wK9eDGEU8uOAAhLhXZZqIz32y75pzOtEX+5NNEv+zCDqTzYeBIq\n"
    "e0rzVt7rZQC0FzhwNERlVU9mT0IlKfPySQMnF15MN/Tj8jof9AHWdO6nyoJXjPPL\n"
    "yjmJ0SkRNG2CTy8jr9ERs21rgCxk0rgVA7V9H9Gc+gtXKTtPhEh7gbyStiNwX3uR\n"
    "IF/LOgS2R4O5dcOHbFXdJCJi9sRHaz0oxqRI9UkX0A==\n"
    "-----END CERTIFICATE-----\n";

static const char * const HARDCODED_PROTECTION_KEY =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAxWNzaIElKXVNPlxn\n"
    "xNUOr9xxYjAaffpTP+k7+DGgx5tSZ1R51rlScpnZTle/3roocuj5AWMdiOp8YD6r\n"
    "/X5r5lOhgYkDgYYABAEsfHbWiSWyGP9Wcu8K0JMHkjzcYOJKuL8dzu1Kex/4f8ET\n"
    "vMZS7Me+P1FFDVUM4ZXAomvMEEtGv2u4apvakttALgCkII+P9ayyguxNnElZwuZc\n"
    "8sDfCO+dChYq8xe1E8yUtkyBJlRSdJeBm5lSMUcOocggIwokbfHL7VChr1J8L3tC\n"
    "oA==\n"
    "-----END PRIVATE KEY-----\n"; // Compiler implicitly adds final null terminator here.

static const char * const HARDCODED_PROTECTION_CHAIN =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEyzCCArOgAwIBAgIUZJkCuqm5BkfFlTaNMIWpSRHQUD0wDQYJKoZIhvcNAQEN\n"
    "BQAwgaIxNzA1BgNVBAMMLlBQS0kgUGxheWdyb3VuZCBJbmZyYXN0cnVjdHVyZSBJ\n"
    "c3N1aW5nIENBIHYyLjAxHjAcBgNVBAsMFUNvcnBvcmF0ZSAgVGVjaG5vbG9neTEo\n"
    "MCYGA1UECwwfRm9yIGludGVybmFsIHRlc3QgcHVycG9zZXMgb25seTEQMA4GA1UE\n"
    "CgwHU2llbWVuczELMAkGA1UEBhMCREUwHhcNMjUwNTIzMTAyODUwWhcNMzAwNTIy\n"
    "MTAyODQ5WjCBrjEqMCgGA1UEAwwhUHJvZHVjdCBQS0kgUGxheWdyb3VuZCBDTVAg\n"
    "U2lnbmVyMRgwFgYDVQQLDA9QUEtJIFBsYXlncm91bmQxHTAbBgNVBAsMFENvcnBv\n"
    "cmF0ZSBUZWNobm9sb2d5MSgwJgYDVQQLDB9Gb3IgaW50ZXJuYWwgdGVzdCBwdXJw\n"
    "b3NlcyBvbmx5MRAwDgYDVQQKDAdTaWVtZW5zMQswCQYDVQQGEwJERTCBmzAQBgcq\n"
    "hkjOPQIBBgUrgQQAIwOBhgAEASx8dtaJJbIY/1Zy7wrQkweSPNxg4kq4vx3O7Up7\n"
    "H/h/wRO8xlLsx74/UUUNVQzhlcCia8wQS0a/a7hqm9qS20AuAKQgj4/1rLKC7E2c\n"
    "SVnC5lzywN8I750KFirzF7UTzJS2TIEmVFJ0l4GbmVIxRw6hyCAjCiRt8cvtUKGv\n"
    "Unwve0Kgo3MwcTAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFFn9fSU/q4v50fLz\n"
    "9IaPLCd/wHS8MBEGA1UdIAQKMAgwBgYEVR0gADAdBgNVHQ4EFgQUsqYFbNQW+QxR\n"
    "u6Rd+rlDBlWHpRwwDgYDVR0PAQH/BAQDAgXgMA0GCSqGSIb3DQEBDQUAA4ICAQBD\n"
    "YjKYifehtT2y1nRXi6IDHYP2EtHMABW5bZHufy4Sth0v2O7me24jYq/+ywdiDKpi\n"
    "IK4wxDmHPlKPn6y/6v7vVocbOrjod/hyaZlcl0hEfjq+SxrYUzYL36vR/CkLC1Al\n"
    "/Tkxhzl0Z7hk55WzbuLBjRRyBpEqj+LA4KHS/3jxuL7ac62LiP9JDWh8DI/r4PeA\n"
    "KRNjLLfVIdqBuRIT41x/jiitkdEwGeU1gmnqL2t0OCb128SLZKfdozvdmh16H738\n"
    "+YMZ5YImAhA3zJchAv4m3xyZhoX83FkqjF4M+WNP4am+qHgq5gModaMY6UsKtaQe\n"
    "h6zbvHM3nuKZqZtormdGfb6s4K/MvBXPegZwkyXRDTyrf2y0tVdU3ViZ1BbO5AYc\n"
    "N+2MunAtHqX8lLjrcJYAlRDJINjDP/m6S/uHRi2Ilpxi9k+g82i+3s4BUONXcyve\n"
    "oka3LspcAslZ6wK9eDGEU8uOAAhLhXZZqIz32y75pzOtEX+5NNEv+zCDqTzYeBIq\n"
    "e0rzVt7rZQC0FzhwNERlVU9mT0IlKfPySQMnF15MN/Tj8jof9AHWdO6nyoJXjPPL\n"
    "yjmJ0SkRNG2CTy8jr9ERs21rgCxk0rgVA7V9H9Gc+gtXKTtPhEh7gbyStiNwX3uR\n"
    "IF/LOgS2R4O5dcOHbFXdJCJi9sRHaz0oxqRI9UkX0A==\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIGMzCCBBugAwIBAgIUSVT+Ya61JDjrqUgv6q38gJ4T+c4wDQYJKoZIhvcNAQEN\n"
    "BQAwgZ4xNDAyBgNVBAMMK1BQS0kgUGxheWdyb3VuZCBJbmZyYXN0cnVjdHVyZSBS\n"
    "b290IENBIHYyLjAxHTAbBgNVBAsMFENvcnBvcmF0ZSBUZWNobm9sb2d5MSgwJgYD\n"
    "VQQLDB9Gb3IgaW50ZXJuYWwgdGVzdCBwdXJwb3NlcyBvbmx5MRAwDgYDVQQKDAdT\n"
    "aWVtZW5zMQswCQYDVQQGEwJERTAeFw0yNTA1MjIxNTUxMzhaFw0zNzA1MTkxNTUx\n"
    "MzdaMIGiMTcwNQYDVQQDDC5QUEtJIFBsYXlncm91bmQgSW5mcmFzdHJ1Y3R1cmUg\n"
    "SXNzdWluZyBDQSB2Mi4wMR4wHAYDVQQLDBVDb3Jwb3JhdGUgIFRlY2hub2xvZ3kx\n"
    "KDAmBgNVBAsMH0ZvciBpbnRlcm5hbCB0ZXN0IHB1cnBvc2VzIG9ubHkxEDAOBgNV\n"
    "BAoMB1NpZW1lbnMxCzAJBgNVBAYTAkRFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A\n"
    "MIICCgKCAgEAwJ5OPdlq7Adwc3aHCdXC+9tP0nZENWKX6boEglPbdJYqZUktxrli\n"
    "UL/zCt9Zs5IIx2z9uV64Ot0Wrtk+aDIQ7emULLZQzm+NOtwBhzEMAgmR8SCgzHAR\n"
    "aLX/e/2GSenTFOHMa0lXRwCiORjM5qF1ufFYsP1usd+JigPTZCKSxSTEgLWMH2q2\n"
    "TqSTwqICd8t4insWcNBfx+lLkEhv0TWAACA4PH4v0ePAZnyiVR6y4IuPrHqYkeeT\n"
    "9Z/JCKdsxA0PEegQBV41+MhsW9WKedzxEFEnzW9Hjy8e2RZn/lQgnTQ+zrrjPJ3F\n"
    "5CkZfDV1OaIt5bG1PydsRdyN0C+Oi0o3Lng8stYf3jwF8Reol6M8cI31spbDheDx\n"
    "BhU5NhTtLnTHjUQ0PkhrKv/LRxWoc7ToxHgOEi96tC7vGpPTGYCbjxMAoUTYwFuV\n"
    "uQM5GybzjUh9WwAVzqgwIsH/XGZNmQEwf9PVMjdtHIMDnX4x+S0ZqoC6q+PIix68\n"
    "FGOQInRzUa+pnoxl+wEsjUZp8EzA89Wo8Uq+ZTmeM9qZ00isaMcnh4RdbqcRUWxz\n"
    "x8HqNaVnZQX0Zg/o1qpMGJ5Ifl7FMHoz9GrPR7obWkGwjx92fpRHIi6yoq5rd6yk\n"
    "aHbQvxwA+kfnfOegWWO0v/1wZJvxI+/kBrC2wj5dBl/aUPEH01+WvDMCAwEAAaNj\n"
    "MGEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRPYykzlMJraNZuvUvM8TMd\n"
    "YtnWdTAdBgNVHQ4EFgQUWf19JT+ri/nR8vP0ho8sJ3/AdLwwDgYDVR0PAQH/BAQD\n"
    "AgGGMA0GCSqGSIb3DQEBDQUAA4ICAQCB1BagOxW736p12p+TK1KhGm6QCwn+knwl\n"
    "SMG9SJ6ZGkT0KXhV/PdHWrYe6N8WPFJSy7ta0WnLbHy23XPtFZXldsVTiDqHvEfG\n"
    "uGmm1hEjaut4YYUyJAV1rcuRdMX52QnJLAFwm6HQxjb/aZmK5XYP+35aeEN5MVaW\n"
    "bzmVr3e8CmXt3xBe13XxaVf15hw/0GudSvO6tfzrKQP6Ri+x2GQwKj+7zWY8J0MA\n"
    "/u4d9h2KSHZ627fMJ8UrZLhdWhlaVOycWKZruzL2mBZdBQ3e7AEBepRFzr9lhYMf\n"
    "DPnalOYHGQ43MNb/gjHnzVCbmCHCVXyMpLry10GhhJk1+i0lcZJQAjdlNjZfr12P\n"
    "Qv6w23DgyDOoKKfQJwud9bW1hcsDErf7muaW4FNjLoXAZ1EmjcOATcUOdkn1eApB\n"
    "SoGwdcfCWd/l+BgyV0/w8/biWHaQwsPYmRxLHQYysv9RgK1Y8RBSulJ3RBES38jJ\n"
    "bwVm+rw7ATo2wymNBM4nl4SxvIWMi662OiYSH3ryaqbXrAC9UPtDD7C8hLmWEg7b\n"
    "e5LijsRbbPYcFDUdR9NJpadlrPsEq+7/oZvBRCaeK1TcAu8dUglNdETBAuF3Dbcx\n"
    "MJRWO2Px4K14KKFCXlm63q8bDGOpzGC2ZozPtLljGg8fIU+hgYcnB6OPdoySdL0u\n"
    "2iDk458bjw==\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIGMTCCBBmgAwIBAgIUde8puSB/m2J/olW0GdDLqA3QRLAwDQYJKoZIhvcNAQEN\n"
    "BQAwgZ4xNDAyBgNVBAMMK1BQS0kgUGxheWdyb3VuZCBJbmZyYXN0cnVjdHVyZSBS\n"
    "b290IENBIHYyLjAxHTAbBgNVBAsMFENvcnBvcmF0ZSBUZWNobm9sb2d5MSgwJgYD\n"
    "VQQLDB9Gb3IgaW50ZXJuYWwgdGVzdCBwdXJwb3NlcyBvbmx5MRAwDgYDVQQKDAdT\n"
    "aWVtZW5zMQswCQYDVQQGEwJERTAgFw0yNTA1MjIxNTQ4NTRaGA8yMDUwMDUxNjE1\n"
    "NDg1M1owgZ4xNDAyBgNVBAMMK1BQS0kgUGxheWdyb3VuZCBJbmZyYXN0cnVjdHVy\n"
    "ZSBSb290IENBIHYyLjAxHTAbBgNVBAsMFENvcnBvcmF0ZSBUZWNobm9sb2d5MSgw\n"
    "JgYDVQQLDB9Gb3IgaW50ZXJuYWwgdGVzdCBwdXJwb3NlcyBvbmx5MRAwDgYDVQQK\n"
    "DAdTaWVtZW5zMQswCQYDVQQGEwJERTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC\n"
    "AgoCggIBAIxoyV9mcP7wKEsEsIXKSSbM1r+7qwQzP5ccW3P5nWPo0gdTqx47kG5c\n"
    "74HcNjHOo0BnvDePs1S9z2LUknTi78jFSv6btLzZg9Kl7ye74yol2j+GmeMhhpmk\n"
    "ABZfRuk6DPAO66Pa/st+lX6aq1MWqPrjneRckTj+lZrl90Gt9Qwmp98FmgyaXYH5\n"
    "nTl3N4kiD+cBom6PBmU2aRnXJZTsz/kNXgIC+871UEmvksbeD+L5nmKbDLhgB/Iy\n"
    "77aNXPogHJe/17V6ofDq9Zrh7xWD9/Q7U93kdKKNnaVY8c8rooNjFUDnx6Kz+faA\n"
    "8S5rDYdOp4o5vzJbWIi62S+fw8crWhD9AjuunBwoZatMFYtGfWKflGkyg6M0htz9\n"
    "6YMMmvZ714suFTT18kNEihTkOqyhUaNhmI/gKVNdP3Mv6RWOavHbXAAxbMsG1GGE\n"
    "Mqw84vIYMul//UDuPtOteSZaARfNVIcNM+ol/xL2tsoDCWZGm3u/1vvIifU4uBa7\n"
    "gC3szG21dXp0JHIAURzEzcJVYu8VMyxF74nUZDFPh0609l3Bgkcs4uNwbmYy0jmN\n"
    "aEXOtj4LDtmdsFVGH6s506SlXY/0mf8Dxkb2/v2lesU/5DKnmAs38YKbky+ILphm\n"
    "i2JrajKBt0macb+qYvfd6vOTeqKeyba/yhwYfMCJ42sI34YXyPN/AgMBAAGjYzBh\n"
    "MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUT2MpM5TCa2jWbr1LzPEzHWLZ\n"
    "1nUwHQYDVR0OBBYEFE9jKTOUwmto1m69S8zxMx1i2dZ1MA4GA1UdDwEB/wQEAwIB\n"
    "hjANBgkqhkiG9w0BAQ0FAAOCAgEAUEAcpPNPyc38aAhHBujONrp/vcCVgZxCBf7I\n"
    "3jBt+lsSUbeC2kza/mu36cH8MLPouoJvVVDBrsJa9+co0pOY/L0XK8qQ7dfIr2Ox\n"
    "lS0JngSQ8SwGhX770OD4wUDhGhHTdRUpzXKwwV7E/YXRxqpMIDWCwF/Z3iiAGcf/\n"
    "Ed/+TEXrwcjaRPEdXoXqtHIQfFkn/HChJzGZOumg/I5y23RSmh3E/97nhW77sAFs\n"
    "WT+DoIUT9NPQXv6pNc2zqtmBzUIfxkmy8EIqqVabX6Fw/w43ADaoHWqBcBjZhWVA\n"
    "BagZKJXqJPbbb6xe1GQWW6Oq3w+tSsL+xeqc5OSjO6EndYzH6dRvhroO5TJWEDxA\n"
    "qv7qFnfJRysLWEBd2OzAAGYGXxTxjnIcOTg9/w5PwH28Cu1QazyP3DYMTL6NdFuE\n"
    "pfHxsAZxZRpPivR/xLqu5htbEuTnGPtLuGTYR+0zParCZSH0VD+N/F68l4kUMovQ\n"
    "oYPq+HXjLP+kF7D6N18HNJA/rGWzhBDp8AHiB+ZtBt4zaWQd7nvQSbwrqVT++lpc\n"
    "R9WDUFkUaYVzKiZKdMLonm7je2MkZbX6+evg6flP7E47CFRKdMEkdzS3Kdw+LzdA\n"
    "1J+h4YEYahG7u1to5uItgkjSrjMgiXBlfEMk2xSKObIfFfxOLrklMv0MKAdhShtV\n"
    "cli9ACs=\n"
    "-----END CERTIFICATE-----\n";



static const char * const HARDCODED_PROTECTION_TRUST_ANCHOR =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDCTCCAmqgAwIBAgIINj6bhzy5IVowCgYIKoZIzj0EAwQwgZMxKTAnBgNVBAMM\n"
    "IFBQS0kgUGxheWdyb3VuZCBFQ0MgUm9vdCBDQSB2MS4wMR0wGwYDVQQLDBRDb3Jw\n"
    "b3JhdGUgVGVjaG5vbG9neTEoMCYGA1UECwwfRm9yIGludGVybmFsIHRlc3QgcHVy\n"
    "cG9zZXMgb25seTEQMA4GA1UECgwHU2llbWVuczELMAkGA1UEBhMCREUwHhcNMTcw\n"
    "ODAyMTA1NzU5WhcNMjkwNzMwMTA1NzU5WjCBkzEpMCcGA1UEAwwgUFBLSSBQbGF5\n"
    "Z3JvdW5kIEVDQyBSb290IENBIHYxLjAxHTAbBgNVBAsMFENvcnBvcmF0ZSBUZWNo\n"
    "bm9sb2d5MSgwJgYDVQQLDB9Gb3IgaW50ZXJuYWwgdGVzdCBwdXJwb3NlcyBvbmx5\n"
    "MRAwDgYDVQQKDAdTaWVtZW5zMQswCQYDVQQGEwJERTCBmzAQBgcqhkjOPQIBBgUr\n"
    "gQQAIwOBhgAEARFIztaxXOsLgjRJpBm5QIxxTTNTtDB34SPh8H624nKOJtm0CD7E\n"
    "vUhfhCu+os5ag1rASEwFcoJm8U4HbCm40hfrALMaKFTE6XARDG/DNlDvGOdOpaDH\n"
    "ZwXvtUalCi/dH2UMKA4AaI6838fElfYAduQSjbJGL3cgNHfHDkcNT7uPcBbWo2Mw\n"
    "YTAdBgNVHQ4EFgQUODjM4scE12q/7HPqbr/Uz88364UwDwYDVR0TAQH/BAUwAwEB\n"
    "/zAfBgNVHSMEGDAWgBQ4OMzixwTXar/sc+puv9TPzzfrhTAOBgNVHQ8BAf8EBAMC\n"
    "AYYwCgYIKoZIzj0EAwQDgYwAMIGIAkIAxe4axxY4utRzQ5o6QXxnfQ6cN8X4WRUy\n"
    "pC0yStrdWUI7kywusIhOyfVD4iWWO6k8L8t6F08hYX/GE1ALGZBwQpwCQgCuiFc8\n"
    "ejZgwnhwfcI9MAxQt7SOGkFyVQboSPwS5EGhLibmBwg+yPkOEQ9M/gcG+S617Se3\n"
    "EfoG8JGbzVYAbb87AQ==\n"
    "-----END CERTIFICATE-----\n"; // Compiler implicitly adds final null terminator here.

static const char * const HARDCODED_ENROLLMENT_TRUST_ANCHOR =
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDFzCCAnigAwIBAgIUQ3MAbaGNp7xiJgRwPQi5Qb4vO04wCgYIKoZIzj0EAwQw\n"
    "gZMxKTAnBgNVBAMMIFBQS0kgUGxheWdyb3VuZCBFQ0MgUm9vdCBDQSB2Mi4wMR0w\n"
    "GwYDVQQLDBRDb3Jwb3JhdGUgVGVjaG5vbG9neTEoMCYGA1UECwwfRm9yIGludGVy\n"
    "bmFsIHRlc3QgcHVycG9zZXMgb25seTEQMA4GA1UECgwHU2llbWVuczELMAkGA1UE\n"
    "BhMCREUwIBcNMjUwNTIyMTU1MzA3WhgPMjA1MDA1MTYxNTUzMDZaMIGTMSkwJwYD\n"
    "VQQDDCBQUEtJIFBsYXlncm91bmQgRUNDIFJvb3QgQ0EgdjIuMDEdMBsGA1UECwwU\n"
    "Q29ycG9yYXRlIFRlY2hub2xvZ3kxKDAmBgNVBAsMH0ZvciBpbnRlcm5hbCB0ZXN0\n"
    "IHB1cnBvc2VzIG9ubHkxEDAOBgNVBAoMB1NpZW1lbnMxCzAJBgNVBAYTAkRFMIGb\n"
    "MBAGByqGSM49AgEGBSuBBAAjA4GGAAQBCgux/cpArds04mXFjqAloZSGBSFph2FJ\n"
    "D2N9ridZnj8IOAEUqM1vgzyWvuHoxK/NmhYOHlWX+ltEnp0a5egQDc8AiIHLx6kA\n"
    "RTHpTojgsrXhQ9kLSmGWfw5unrahu8N3HiwYsOR+Lg8kJ3SEaIVnI9HyKgxl1Bia\n"
    "CLjT6bDqyCv2B4qjYzBhMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUfb/x\n"
    "wMgvwlS0BD6lrSAXPQLcg9kwHQYDVR0OBBYEFH2/8cDIL8JUtAQ+pa0gFz0C3IPZ\n"
    "MA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDBAOBjAAwgYgCQgDQ2VkCW97Aahut\n"
    "kuJ8k0a5ybeGq/5bKufY7+QctKasrAGNiOE9CXAzxcyPwGV0XW+BlkeTAZYhCgt4\n"
    "Je1Mt1MjfwJCASlpFyA3/Kx4q3whDaARR90Ioz4NhUNbq3AIG+fTmTRNUedH3N10\n"
    "p0kS0ZIotlK3TlQO6seWUOMIcmtIFL0pccu+\n"
    "-----END CERTIFICATE-----\n";



/* Read file to (binary) string */
static int read_file(unsigned char **contents, const char *filename)
{
    FILE *fileObject = NULL;
    long fileSize = 0;
    size_t readBytes = 0;
    unsigned char *buffer = NULL;

    *contents = NULL;

    fileObject = fopen(filename, "rb");
    if (fileObject == NULL) {
        CMPERRV("fopen of %s failed: %s\r\n", filename, strerror(errno));
        return -1;
    }

    if (fseek(fileObject, 0, SEEK_END) != 0) {
        CMPERRV("fseek end failed for %s: %s\r\n", filename, strerror(errno));
        fclose(fileObject);
        return -1;
    }
    fileSize = ftell(fileObject);
    if (fileSize < 0) {
        CMPERRV("ftell failed for %s: %s\r\n", filename, strerror(errno));
        fclose(fileObject);
        return -1;
    }
    if ((size_t) fileSize >= MAX_FILE_SIZE) {
        CMPERRV("file %s too large for loading, len=%ld\r\n", filename, fileSize);
        fclose(fileObject);
        return -1;
    }
    if (fseek(fileObject, 0, SEEK_SET) != 0) {
        CMPERRV("fseek set failed for %s: %s\r\n", filename, strerror(errno));
        fclose(fileObject);
        return -1;
    }

    buffer = calloc(1, (size_t) fileSize + 1);
    if (buffer == NULL) {
        CMPERRV("alloc failed for %s\r\n", filename);
        fclose(fileObject);
        return -1;
    }

    readBytes = fread(buffer, 1, (size_t) fileSize, fileObject);
    if (readBytes != (size_t) fileSize) {
        CMPERRV("wrong fread of %s: %zu != %ld\r\n", filename, readBytes, fileSize);
        free(buffer);
        fclose(fileObject);
        return -1;
    }
    buffer[readBytes] = '\0';

    if (fclose(fileObject) != 0) {
        CMPERRV("fclose of %s failed: %s\r\n", filename, strerror(errno));
        free(buffer);
        return -1;
    }

    *contents = buffer;
    return (int) readBytes;
}

static int write_file(unsigned char *content, size_t len, const char *filename,
                      int append)
{
    FILE *fileObject = fopen(filename, append ? "a" : "w");
    if (fileObject == NULL) {
        CMPERRV("fopen of %s failed: %s\r\n", filename,
                strerror(errno));
        return -1;
    }
    size_t writtenBytes = fwrite(content, 1, len, fileObject);
    if (len != writtenBytes) {
        CMPERRV("====ERROR==== wrong f_read of %s: " SIZEFMT " != " SIZEFMT " \r\n", filename,
                writtenBytes,  len);
        return -1;
    }
    int error = fclose(fileObject);
    if (error) {
        CMPERRV("f_close of %s failed: %s\r\n", filename,
                strerror(errno));
        return -1;
    }
    return (int) writtenBytes;

}

/* **************************************************************** */
/* Parse certificates from a file or use a hardcoded value for specific paths */
int append_certs_from_pem(mbedtls_x509_crt *crt, const char *path_to_pem)
{
    int ret = 0;
    unsigned char *pem_str = NULL;
    int len = 0;
    int is_dynamic_alloc = 0;

    // Check if the path matches the special protection certificate path
    if (strcmp(path_to_pem, PATH_TO_PROTECTION_CERT) == 0) {
        CMPDBGV("Using hardcoded protection certificate for path: %s", path_to_pem);
        pem_str = (unsigned char *)HARDCODED_PROTECTION_CERT;
        len = strlen(HARDCODED_PROTECTION_CERT);
        // is_dynamic_alloc remains false, as we are using a static string literal
    } 
    else if (strcmp(path_to_pem, PATH_TO_PROTECTION_CHAIN) == 0) {
        CMPDBGV("Using hardcoded protection certificate for path: %s", path_to_pem);
        pem_str = (unsigned char *)HARDCODED_PROTECTION_CHAIN;
        len = strlen(HARDCODED_PROTECTION_CHAIN);
        // is_dynamic_alloc remains false, as we are using a static string literal        
    }
    else if (strcmp(path_to_pem, PATH_TO_PROTECTION_TRUST_ANCHOR_PEM) == 0) {
        CMPDBGV("Using hardcoded protection certificate for path: %s", path_to_pem);
        pem_str = (unsigned char *)HARDCODED_PROTECTION_TRUST_ANCHOR;
        len = strlen(HARDCODED_PROTECTION_TRUST_ANCHOR);
        // is_dynamic_alloc remains false, as we are using a static string literal        
    }
    else if (strcmp(path_to_pem, PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM) == 0) {
        CMPDBGV("Using hardcoded enrollment certificate for path: %s", path_to_pem);
        pem_str = (unsigned char *)HARDCODED_ENROLLMENT_TRUST_ANCHOR;
        len = strlen(HARDCODED_ENROLLMENT_TRUST_ANCHOR);
        // is_dynamic_alloc remains false, as we are using a static string literal        
    }
    else if (strcmp(path_to_pem, TLS_CLIENT_CERT) == 0) {
        CMPDBGV("Using hardcoded enrollment certificate for path: %s", path_to_pem);
        pem_str = (unsigned char *)HARDCODED_TLS_CLIENT_CERT;
        len = strlen(HARDCODED_TLS_CLIENT_CERT);
        // is_dynamic_alloc remains false, as we are using a static string literal        
    }
    else if (strcmp(path_to_pem, TLS_SERVER_ROOT) == 0) {
        CMPDBGV("Using hardcoded enrollment certificate for path: %s", path_to_pem);
        pem_str = (unsigned char *)HARDCODED_TLS_SERVER_ROOT;
        len = strlen(HARDCODED_TLS_SERVER_ROOT);
        // is_dynamic_alloc remains false, as we are using a static string literal        
    }
    else {
        len = read_file(&pem_str, path_to_pem);
        if (len < 0) {
            CMPERRV("Loading certs from %s FAILED", path_to_pem);
            return FILE_ERR_FILE_READ;
        }
        is_dynamic_alloc = 1;
    }

    if (len == 0) {
        CMPDBGV("Empty certs data for %s", path_to_pem);
        // The original logic passed empty data to mbedtls_x509_crt_parse,
        // which would likely result in an error from mbedTLS.
        // We maintain this behavior for consistency.
    } else {
        // mbedtls_x509_crt_parse expects the buffer to be null-terminated.
        // strlen gives length WITHOUT null terminator. Adding +1 passes the
        // total buffer size including the expected null terminator.
        // This assumes read_file also null-terminates the buffer it returns.
        ret = mbedtls_x509_crt_parse(crt, pem_str, len + 1);
    }

    if (ret != 0) {
        CMPERRV("Parsing certs FAILED - mbedtls_x509_crt_parse returned -0x%04x for %s",
                -ret, path_to_pem);
    }

    if (is_dynamic_alloc && pem_str != NULL) {
        free(pem_str);
    }
    
    return ret;
}
/* **************************************************************** */
/* Parse CRLs from a file */
int append_crls_from_pem(mbedtls_x509_crl *crl, const char *path_to_pem)
{
    int ret = 0, len = 0;
    unsigned char *pem_str = NULL;
    len = read_file(&pem_str, path_to_pem);
    if (len < 0) {
        CMPERRV("Loading CRLs from %s FAILED", path_to_pem);
        return FILE_ERR_FILE_READ;
    }

    if (len == 0) {
        CMPDBGV("Empty CRLs file %s", path_to_pem);
    } else {
        ret = mbedtls_x509_crl_parse(crl, pem_str, len + 1);
    }
    if (ret != 0) {
        CMPERRV("parsing CRLs FAILED - mbedtls_x509_crl_parse returned -0x%04x",
                -ret);
    }
    return ret;
}

/* **************************************************************** */
/* Parse a private key without password */
int parse_key_from_pem(mbedtls_pk_context *pk_ctx,
                       const char *path_to_pem,
                       mbedtls_ctr_drbg_context *ctr_drbg)
{
    unsigned char *pem_str = NULL;
    int len = 0;
    int is_dynamic_alloc = 0;
    int ret = 0;

    mbedtls_pk_init(pk_ctx);
  
    if (strcmp(path_to_pem, PATH_TO_PROTECTION_KEY) == 0) {
        CMPDBGV("Using hardcoded protection key for path: %s", path_to_pem);
        pem_str = (unsigned char *)HARDCODED_PROTECTION_KEY;
        len = strlen(HARDCODED_PROTECTION_KEY);
        // is_dynamic_alloc remains false, as we are using a static string literal
    }
    else if (strcmp(path_to_pem, TLS_CLIENT_KEY) == 0) {
        CMPDBGV("Using hardcoded protection key for path: %s", path_to_pem);
        pem_str = (unsigned char *)HARDCODED_TLS_CLIENT_KEY;
        len = strlen(HARDCODED_TLS_CLIENT_KEY);
        // is_dynamic_alloc remains false, as we are using a static string literal
    }    
    else {
        len = read_file(&pem_str, path_to_pem);
        if (len <= 0) {
            CMPERRV("Loading KEY from %s FAILED", path_to_pem);
            return FILE_ERR_FILE_READ;
        }
        is_dynamic_alloc = 1;
    }

    if (pem_str == NULL || len <= 0) {
        CMPERRV("No key data available for %s", path_to_pem);
        ret = FILE_ERR_FILE_READ;
        goto cleanup;
    }

    ret = mbedtls_pk_parse_key(pk_ctx,
                               pem_str,
                               len + 1,
                               NULL,
                               0,
                               mbedtls_ctr_drbg_random,
                               ctr_drbg);
    if (ret != 0) {
        CMPERRV("parsing key FAILED - mbedtls_pk_parse_key returned -0x%04x",
                -ret);
    }

cleanup:
    if (is_dynamic_alloc && pem_str != NULL) {
        free(pem_str);
    }
    return ret;
}

/* **************************************************************** */

int write_private_key_pem(mbedtls_pk_context *key, const char *output_file)
{

    int ret = mbedtls_pk_write_key_pem(key, content_buffer, MAX_FILE_SIZE - 1);
    if (ret != 0) {
        CMPDBGV(
            "Writing key to pem FAILED, mbedtls_pk_write_key_pem() returned %d",
            ret);
        return ret;
    }
    content_buffer[MAX_FILE_SIZE - 1] = '\0';
    if (write_file(content_buffer, strlen((char *) content_buffer), output_file,
                   0) <= 0) {
        CMPERRV("Writing key to pem FAILED\n %s", output_file);
        return -1;
    }
    CMPINFOV("Private key written to %s", output_file);
    return 0;
}

/* **************************************************************** */

int write_cert_pem(mbedtls_x509_crt *cert, const char *output_file)
{

    int i = 0;
    while (cert) {
        size_t olen = 0;
        size_t write_len = 0;
        int ret;
        if ((ret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n",
                                            "-----END CERTIFICATE-----\n", cert->raw.p,
                                            cert->raw.len,
                                            content_buffer, MAX_FILE_SIZE, &olen)) != 0) {
            CMPDBGV(
                "Writing certificate to pem FAILED, mbedtls_pem_write_buffer() returned %d",
                ret);
            return ret;
        }
        write_len = olen;
        if (write_len > 0 && content_buffer[write_len - 1] == '\0') {
            write_len--;
        }
        if (write_file(content_buffer, write_len, output_file, i != 0) <= 0) {
            CMPERRV("Writing CERT to file FAILED\n %s", output_file);
            return -1;
        }
        i++;
        cert = cert->next;
    }
    CMPINFOV("%d certificate(s) written to %s", i, output_file);
    return 0;
}
