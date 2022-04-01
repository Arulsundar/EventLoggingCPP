#include <stdio.h>
#include <windows.h>
#include "WinLog.h"

#include <string.h>
#include <string>
#include <pch.h>

using namespace std;
using convert_t = codecvt_utf8<wchar_t>;
wstring_convert<convert_t, wchar_t> strconverter;

#pragma comment(lib, "wevtapi.lib")
#define ARRAY_SIZE 1000

struct SearchRecord {
    string type;
    string time;
    string source;
    string eid;

};
//EVT_HANDLE ConnectToRemote(string ip, string user,string password);
DWORD PrintResults(EVT_HANDLE hResults, vector<SearchRecord*>* searchRecordResult, long int position);
DWORD PrintEvent(EVT_HANDLE hEvent, vector<SearchRecord*>* searchRecordResult);



void takeLogs(EVT_HANDLE hRemoteHandle,vector<SearchRecord*>* searchRecordResult, long int position)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hResults = NULL;
    const wchar_t* channelPath = L"Application";
    const wchar_t* query = L"*";
    //cout << hRemoteHandle;

    hResults = EvtQuery(hRemoteHandle, channelPath, query, EvtQueryChannelPath |
        EvtQueryForwardDirection);
    if (hResults == NULL) {                             //Check for an error
        status = GetLastError();
        if (status == ERROR_EVT_CHANNEL_NOT_FOUND)
            cout << "ERROR : Channel not found...\n";
        else if (status == ERROR_EVT_INVALID_QUERY)
            cout << "ERROR : Invalid Query...\n";
        else
            cout << "ERROR STATUS : " << status;
        goto Cleanup;
    }

    PrintResults(hResults, searchRecordResult, position);

Cleanup:
    if (hResults)
        EvtClose(hResults);
    
}
void closeEventLog(EVT_HANDLE handle)
{
    if (handle)
        EvtClose(handle);
}
EVT_HANDLE ConnectToRemote(string ip, string user, string password)
{
    EVT_HANDLE hRemote = NULL;
    EVT_RPC_LOGIN Credentials;

    /*std::wstring comp_name = L"172.24.130.115";
    std::wstring user_name = L"administrator";
    std::wstring password = L"Qazxsw(426)";*/

    wstring comp_name = strconverter.from_bytes(ip);
    wstring user_name = strconverter.from_bytes(user);
    wstring pass = strconverter.from_bytes(password);


    RtlZeroMemory(&Credentials, sizeof(EVT_RPC_LOGIN));
    if (ip == "localhost")
    {
        Credentials.Server = NULL;
        Credentials.Domain = NULL;
        Credentials.User = NULL;
        Credentials.Password = NULL;
        Credentials.Flags = EvtRpcLoginAuthNegotiate;
    }
    else
    {
        Credentials.Server = &comp_name[0];
        Credentials.Domain = NULL;
        Credentials.User = &user_name[0];
        Credentials.Password = &pass[0];
        Credentials.Flags = EvtRpcLoginAuthNegotiate;
    }


    hRemote = EvtOpenSession(EvtRpcLogin, &Credentials, 0, 0);

    SecureZeroMemory(&Credentials, sizeof(EVT_RPC_LOGIN));

    return hRemote;
}

DWORD PrintResults(EVT_HANDLE hResults,vector<SearchRecord*>* searchRecordResult, long int position)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hEvents[ARRAY_SIZE];
    DWORD dwReturned = 0;
    int j = 1;
    if (!EvtSeek(hResults, position, NULL, 0, EvtSeekRelativeToCurrent))
    {
        wprintf(L"EvtSeek failed with %lu\n", GetLastError());
    }

    while (true)
    {
      
        if (!EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned))
        {
            if (ERROR_NO_MORE_ITEMS != (status = GetLastError()))
            {
                wprintf(L"EvtNext failed with %lu\n", status);
            }

            goto cleanup;
        }


        for (DWORD i = 0; i < dwReturned; i++)
        {
            //cout << "Index" << j++;
            if (ERROR_SUCCESS == (status = PrintEvent(hEvents[i], searchRecordResult)))
            {
                EvtClose(hEvents[i]);
                hEvents[i] = NULL;
            }
            else
            {
                goto cleanup;
            }
        }
        Sleep(5000);
    }

cleanup:

    for (DWORD i = 0; i < dwReturned; i++)
    {
        if (NULL != hEvents[i])
            EvtClose(hEvents[i]);
    }

    return status;
}
DWORD PrintEvent(EVT_HANDLE hEvent,vector<SearchRecord*> *searchRecordResult)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hContext = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    PEVT_VARIANT pRenderedValues = NULL;
    WCHAR wsGuid[50];
    LPWSTR pwsSid = NULL;
    ULONGLONG ullTimeStamp = 0;
    ULONGLONG ullNanoseconds = 0;
    SYSTEMTIME st;
    FILETIME ft;


    hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    if (NULL == hContext)
    {
        wprintf(L"EvtCreateRenderContext failed with %lu\n", status = GetLastError());

    }

    if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
    {
        if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
            if (pRenderedValues)
            {
                EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
                wprintf(L"malloc failed\n");
                status = ERROR_OUTOFMEMORY;
            }
        }

        if (ERROR_SUCCESS != (status = GetLastError()))
        {
            wprintf(L"EvtRender failed with %d\n", GetLastError());

        }
    }


    DWORD EventID = pRenderedValues[EvtSystemEventID].UInt16Val;
    if (EvtVarTypeNull != pRenderedValues[EvtSystemQualifiers].Type)
    {
        EventID = MAKELONG(pRenderedValues[EvtSystemEventID].UInt16Val, pRenderedValues[EvtSystemQualifiers].UInt16Val);
    }
    ostringstream temp;
    temp << EventID;
    string eid = temp.str();


    ullTimeStamp = pRenderedValues[EvtSystemTimeCreated].FileTimeVal;
    ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
    ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);

    FileTimeToSystemTime(&ft, &st);
    ostringstream mon1, day1, year1, hour1, min1, sec1, mil1;
    mon1 << st.wMonth; day1 << st.wDay; year1 << st.wYear; hour1 << st.wHour; min1 << st.wMinute; sec1 << st.wSecond;
    string mon = mon1.str(); string day = day1.str(); string year = year1.str(); string hour = hour1.str(); string min = min1.str(); string sec = sec1.str();
    string time = year + "-" + mon + "-" + day + "T" + hour + ":" + min + ":" + sec;
    
    SearchRecord* pRecord = new SearchRecord();
    pRecord->type = CW2A(pRenderedValues[EvtSystemProviderName].StringVal);
    pRecord->time = time;
    pRecord->eid = eid;
    pRecord->source = CW2A(pRenderedValues[EvtSystemComputer].StringVal);
    searchRecordResult->push_back(pRecord);

    return status;
}

extern "C"
JNIEXPORT jlong JNICALL Java_WinLog_openEventLog
(JNIEnv* env, jobject obj, jstring machine,jstring user,jstring password) 
{

    //machine
    const jclass machineClass = env->GetObjectClass(machine);
    const jmethodID machineBytes = env->GetMethodID(machineClass, "getBytes", "(Ljava/lang/String;)[B");
    const jbyteArray machineJbytes = (jbyteArray)env->CallObjectMethod(machine, machineBytes, env->NewStringUTF("UTF-8"));

    size_t machinelength = (size_t)env->GetArrayLength(machineJbytes);
    jbyte* machinepBytes = env->GetByteArrayElements(machineJbytes, NULL);

    string ip = string((char*)machinepBytes, machinelength);
    env->ReleaseByteArrayElements(machineJbytes, machinepBytes, JNI_ABORT);

    env->DeleteLocalRef(machineJbytes);
    env->DeleteLocalRef(machineClass);

    //user
    const jclass userClass = env->GetObjectClass(user);
    const jmethodID userBytes = env->GetMethodID(userClass, "getBytes", "(Ljava/lang/String;)[B");
    const jbyteArray userJbytes = (jbyteArray)env->CallObjectMethod(user, userBytes, env->NewStringUTF("UTF-8"));

    size_t userlength = (size_t)env->GetArrayLength(userJbytes);
    jbyte* userpBytes = env->GetByteArrayElements(userJbytes, NULL);

    string username = string((char*)userpBytes, userlength);
    env->ReleaseByteArrayElements(userJbytes, userpBytes, JNI_ABORT);

    env->DeleteLocalRef(userJbytes);
    env->DeleteLocalRef(userClass);

    //password
    const jclass stringClass = env->GetObjectClass(password);
    const jmethodID getBytes = env->GetMethodID(stringClass, "getBytes", "(Ljava/lang/String;)[B");
    const jbyteArray stringJbytes = (jbyteArray)env->CallObjectMethod(password, getBytes, env->NewStringUTF("UTF-8"));

    size_t length = (size_t)env->GetArrayLength(stringJbytes);
    jbyte* pBytes = env->GetByteArrayElements(stringJbytes, NULL);

    string pwd = string((char*)pBytes, length);
    env->ReleaseByteArrayElements(stringJbytes, pBytes, JNI_ABORT);

    env->DeleteLocalRef(stringJbytes);
    env->DeleteLocalRef(stringClass);

    EVT_HANDLE h = ConnectToRemote(ip,username ,pwd);
    
    return (jlong)h;
}
extern "C"
JNIEXPORT jobjectArray JNICALL Java_WinLog_takeLogs
(JNIEnv* env, jobject obj, jlong handle, jlong pointer) 
{

    std::vector<SearchRecord*> searchRecordResult;
    EVT_HANDLE h = (EVT_HANDLE)handle;
    takeLogs(h,&searchRecordResult,pointer);
    jclass cls_Properties = env->FindClass("java/util/Properties");
    jmethodID mid_Properties_ctor = env->GetMethodID(cls_Properties, "<init>", "()V");
    jmethodID mid_Properties_put = env->GetMethodID(cls_Properties, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    jstring key_type = env->NewStringUTF("type");
    jstring key_time = env->NewStringUTF("time");
    jstring key_source = env->NewStringUTF("source");
    jstring key_eid = env->NewStringUTF("eid");

    jobjectArray ret = env->NewObjectArray(searchRecordResult.size(), cls_Properties, 0);
    SearchRecord* result;
    for (int i = 0; i < searchRecordResult.size(); i++) {
        result = searchRecordResult[i];
        env->PushLocalFrame(5);
        jobject prop = env->NewObject(cls_Properties, mid_Properties_ctor);
        env->CallObjectMethod(prop, mid_Properties_put, key_type, env->NewStringUTF(result->type.c_str()));
        env->CallObjectMethod(prop, mid_Properties_put, key_time, env->NewStringUTF(result->time.c_str()));
        env->CallObjectMethod(prop, mid_Properties_put, key_source, env->NewStringUTF(result->source.c_str()));
        env->CallObjectMethod(prop, mid_Properties_put, key_eid, env->NewStringUTF(result->eid.c_str()));
        prop = env->PopLocalFrame(prop);
        env->SetObjectArrayElement(ret, i, prop);
    }

    return ret;
}
extern "C"
JNIEXPORT void JNICALL Java_WinLog_closeEventLog
(JNIEnv* env, jobject obj, jlong handle) {
    EVT_HANDLE h = (EVT_HANDLE)handle;
    CloseEventLog(h);
}