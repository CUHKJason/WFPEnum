#include <stdio.h>
#include <windows.h>
#include <stdint.h>
#include "beacon.h"
#include "bofdefs.h"
#include "util.h"



HANDLE openFile(const char* filename) {
    HANDLE file = KERNEL32$CreateFileA(
        filename,               // File name
        GENERIC_WRITE,          // Desired access
        0,                      // Share mode
        NULL,                   // Security attributes
        CREATE_ALWAYS,          // Creation disposition
        FILE_ATTRIBUTE_NORMAL,  // File attributes
        NULL                    // Template file handle
    );
    if (file == INVALID_HANDLE_VALUE) {
        err("Could not open file (error %lu)\n", KERNEL32$GetLastError());
        return NULL;
    }

    return file;
}

void writeToFile(HANDLE file, const char* str) {
    DWORD bytesWritten;
    KERNEL32$WriteFile(file, str, (DWORD)MSVCRT$strlen(str), &bytesWritten, NULL);
}

void printGUID(GUID guid, HANDLE file) {
    wchar_t guid_str[39]; // Buffer for GUID string representation
    int len = OLE32$StringFromGUID2(&guid, guid_str, 39);
    if (len > 0) {
        char buffer[512];
        MSVCRT$sprintf_s(buffer, sizeof(buffer), "%ls", guid_str);
        writeToFile(file, buffer);
    }
}

// Define WFP filter flags
#define FWPM_FILTER_FLAG_NONE 0x00000000
#define FWPM_FILTER_FLAG_PERSISTENT 0x00000001
#define FWPM_FILTER_FLAG_BOOTTIME 0x00000002
#define FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT 0x00000004
#define FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT 0x00000008
#define FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED 0x00000010
#define FWPM_FILTER_FLAG_DISABLED 0x00000020
#define FWPM_FILTER_FLAG_INDEXED 0x00000040
#define FWPM_FILTER_FLAG_HAS_SECURITY_REALM_PROVIDER_CONTEXT 0x00000080

const char* convertFilterFlags(UINT32 flags) {
    static char buffer[256] = {0};
    buffer[0] = '\0'; // Clear buffer

    if (flags == FWPM_FILTER_FLAG_NONE) {
        MSVCRT$strcat_s(buffer, sizeof(buffer), "FWPM_FILTER_FLAG_NONE");
        return buffer;
    }

    int first = 1;
    if (flags & FWPM_FILTER_FLAG_PERSISTENT) {
        MSVCRT$strcat_s(buffer, sizeof(buffer), first ? "FWPM_FILTER_FLAG_PERSISTENT" : "|FWPM_FILTER_FLAG_PERSISTENT");
        first = 0;
    }
    if (flags & FWPM_FILTER_FLAG_BOOTTIME) {
        MSVCRT$strcat_s(buffer, sizeof(buffer), first ? "FWPM_FILTER_FLAG_BOOTTIME" : "|FWPM_FILTER_FLAG_BOOTTIME");
        first = 0;
    }
    if (flags & FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT) {
        MSVCRT$strcat_s(buffer, sizeof(buffer), first ? "FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT" : "|FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT");
        first = 0;
    }
    if (flags & FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
        MSVCRT$strcat_s(buffer, sizeof(buffer), first ? "FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT" : "|FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT");
        first = 0;
    }
    if (flags & FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED) {
        MSVCRT$strcat_s(buffer, sizeof(buffer), first ? "FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED" : "|FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED");
        first = 0;
    }
    if (flags & FWPM_FILTER_FLAG_DISABLED) {
        MSVCRT$strcat_s(buffer, sizeof(buffer), first ? "FWPM_FILTER_FLAG_DISABLED" : "|FWPM_FILTER_FLAG_DISABLED");
        first = 0;
    }
    if (flags & FWPM_FILTER_FLAG_INDEXED) {
        MSVCRT$strcat_s(buffer, sizeof(buffer), first ? "FWPM_FILTER_FLAG_INDEXED" : "|FWPM_FILTER_FLAG_INDEXED");
        first = 0;
    }
    if (flags & FWPM_FILTER_FLAG_HAS_SECURITY_REALM_PROVIDER_CONTEXT) {
        MSVCRT$strcat_s(buffer, sizeof(buffer), first ? "FWPM_FILTER_FLAG_HAS_SECURITY_REALM_PROVIDER_CONTEXT" : "|FWPM_FILTER_FLAG_HAS_SECURITY_REALM_PROVIDER_CONTEXT");
        first = 0;
    }
    return buffer;
}

// Define the action type constants
#define FWP_ACTION_FLAG_TERMINATING     (0x00001000)
#define FWP_ACTION_FLAG_NON_TERMINATING (0x00002000)
#define FWP_ACTION_FLAG_CALLOUT         (0x00004000)
#define FWP_ACTION_BLOCK                (0x1 | FWP_ACTION_FLAG_TERMINATING)
#define FWP_ACTION_PERMIT               (0x2 | FWP_ACTION_FLAG_TERMINATING)
#define FWP_ACTION_CALLOUT_TERMINATING  (0x3 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_TERMINATING)
#define FWP_ACTION_CALLOUT_INSPECTION    (0x4 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_NON_TERMINATING)
#define FWP_ACTION_CALLOUT_UNKNOWN       (0x5 | FWP_ACTION_FLAG_CALLOUT)
#define FWP_ACTION_CONTINUE              (0x6 | FWP_ACTION_FLAG_NON_TERMINATING)
#define FWP_ACTION_NONE                  (0x7)
#define FWP_ACTION_NONE_NO_MATCH         (0x8)


const char* convertActionType(UINT32 actionType) {
    switch (actionType) {
        case FWP_ACTION_BLOCK:
            return "FWP_ACTION_BLOCK";
        case FWP_ACTION_PERMIT:
            return "FWP_ACTION_PERMIT";
        case FWP_ACTION_CALLOUT_TERMINATING:
            return "FWP_ACTION_CALLOUT_TERMINATING";
        case FWP_ACTION_CALLOUT_INSPECTION:
            return "FWP_ACTION_CALLOUT_INSPECTION";
        case FWP_ACTION_CALLOUT_UNKNOWN:
            return "FWP_ACTION_CALLOUT_UNKNOWN";
        case FWP_ACTION_CONTINUE:
            return "FWP_ACTION_CONTINUE";
        case FWP_ACTION_NONE:
            return "FWP_ACTION_NONE";
        case FWP_ACTION_NONE_NO_MATCH:
            return "FWP_ACTION_NONE_NO_MATCH";
        default:
            return "UNKNOWN";
    }
}

void handleConditionMatchType(UINT32 type, HANDLE file)
{
    char buffer2[1000];
    if (type == 0) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "|Equal|");
    }
    else if (type == 1) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "|Greater|");
    }
    else if (type == 2) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "|Less|");
    }
    else if (type == 3) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "|Greater or Equal|");
    }
    else if (type == 4) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "|Less or Equal|");
    }
    else if (type == 5) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "|Range|");
    }
    else if (type == 6) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "|Flags All Set|");
    }
    else if (type == 7) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "|Flags Any Set|");
    }
    else if (type == 8) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "|Flags Non Set|");
    }
    else if (type == 9) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "|Equal Case Insensitive|");
    }
    else if (type == 10) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "|Not Equal|");
    }
    else if (type == 11) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "|Prefix|");
    }
    else if (type == 12) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "|Not Prefix|");
    }
    else {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "|Unknown Match Type|");
    }
    writeToFile(file, buffer2);
    return;
}

void handleWeight(FWP_VALUE0* value, HANDLE file)
{
    char buffer2[1000];
    if (value->type == FWP_UINT64) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), ",%llu (uint64)", *(value->uint64));
    }
    else if (value->type == FWP_UINT8) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), ",%u (uint8)", value->uint8);
    }
    else if (value->type == FWP_EMPTY) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), ",Unknown weight");
    }
    else {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), ",Unknown weight");
    }
    writeToFile(file, buffer2);
    return;
}

void handleConditionValue(FWP_CONDITION_VALUE0* value, HANDLE file)
{
    char buffer2[1000];
    if (value->type == FWP_UINT8) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "%u (uint8)\"", value->uint8);
    }
    else if (value->type == FWP_UINT16) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "%u (uint16)\"", value->uint16);
    }
    else if (value->type == FWP_UINT32) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "%u (uint32)\"", value->uint32);
    }
    else if (value->type == FWP_UINT64) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "%llu (uint64)\n", *(value->uint64));
        //MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "avoid error (uint64)\"");
    }
    else if (value->type == FWP_INT8) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "%d (int8)\"", value->int8);
    }
    else if (value->type == FWP_INT16) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "%d (int16)\"", value->int16);
    }
    else if (value->type == FWP_INT32) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "%d (int32)\"", value->int32);
    }
    else if (value->type == FWP_INT64) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "%lld (int64)\n", *(value->int64));
        //MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "avoid error (int64)\"");
    }
    else if (value->type == FWP_FLOAT) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "%f (float32)\"", value->float32);
    }
    else if (value->type == FWP_DOUBLE) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "%lf (double64)\"", value->double64);
    }
    else if (value->type == FWP_BYTE_BLOB_TYPE) {
        if (value->byteBlob) {
            MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "%lu (blob)\"", value->byteBlob->size);
        }
        else {
            MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "NULL (blob)\"");
        }
        
    }
    else if (value->type == FWP_BYTE_ARRAY16_TYPE) {
        //MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "avoid error (FWP_BYTE_ARRAY16_TYPE)\n");
        FWP_BYTE_ARRAY16* byteArray16 = value->byteArray16;
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "");
        for (int i = 0; i < 16; i++) {
            MSVCRT$sprintf_s(buffer2 + MSVCRT$strlen(buffer2), sizeof(buffer2) - MSVCRT$strlen(buffer2), "%02X", byteArray16->byteArray16[i]);
            if (i < 15) {
                MSVCRT$sprintf_s(buffer2 + MSVCRT$strlen(buffer2), sizeof(buffer2) - MSVCRT$strlen(buffer2), " "); // Add space between bytes
            }
        }
        MSVCRT$sprintf_s(buffer2 + MSVCRT$strlen(buffer2), sizeof(buffer2) - MSVCRT$strlen(buffer2), " (byte array 16)\"");
    }
    else if (value->type == FWP_SID) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "avoid error (FWP_SID)\"");
    }
    else if (value->type == FWP_SECURITY_DESCRIPTOR_TYPE) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "avoid error (FWP_SECURITY_DESCRIPTOR_TYPE)\"");
    }
    else if (value->type == FWP_TOKEN_INFORMATION_TYPE) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "avoid error (FWP_TOKEN_INFORMATION_TYPE)\"");
    }
    else if (value->type == FWP_TOKEN_ACCESS_INFORMATION_TYPE) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "avoid error (FWP_TOKEN_ACCESS_INFORMATION_TYPE)\"");
    }
    else if (value->type == FWP_UNICODE_STRING_TYPE) {
        //MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "avoid error (FWP_UNICODE_STRING_TYPE)\n");
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "%ls (unicode string)\"", value->unicodeString);
    }
    else if (value->type == FWP_BYTE_ARRAY6_TYPE) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "avoid error (FWP_BYTE_ARRAY6_TYPE)\"");
        // for (int i = 0; i < 6; i++) {
        //     MSVCRT$sprintf_s(buffer2 + MSVCRT$strlen(buffer2), sizeof(buffer2) - MSVCRT$strlen(buffer2), "%02X", value->byteArray6[i]);
        // }
        // MSVCRT$sprintf_s(buffer2 + MSVCRT$strlen(buffer2), sizeof(buffer2) - MSVCRT$strlen(buffer2), " (byte array 6)\n");
    }
    else if (value->type == FWP_SINGLE_DATA_TYPE_MAX) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "avoid error (FWP_SINGLE_DATA_TYPE_MAX)\"");
    }
    else if (value->type == FWP_V4_ADDR_MASK) {
        FWP_V4_ADDR_AND_MASK* addrAndMask = value->v4AddrMask;
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "Address: %u, Mask: %u\"", addrAndMask->addr, addrAndMask->mask);
        
    }
    else if (value->type == FWP_V6_ADDR_MASK) {
        FWP_V6_ADDR_AND_MASK* addrAndMask = value->v6AddrMask;
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "Address: ");
        for (int i = 0; i < 16; i++) {
            MSVCRT$sprintf_s(buffer2 + MSVCRT$strlen(buffer2), sizeof(buffer2) - MSVCRT$strlen(buffer2), "%02X", addrAndMask->addr[i]);
            if (i < 15) {
                MSVCRT$sprintf_s(buffer2 + MSVCRT$strlen(buffer2), sizeof(buffer2) - MSVCRT$strlen(buffer2), ":"); // Add colon between bytes
            }
        }
        MSVCRT$sprintf_s(buffer2 + MSVCRT$strlen(buffer2), sizeof(buffer2) - MSVCRT$strlen(buffer2), ", Prefix Length: %u\"", addrAndMask->prefixLength);
    }
    else if (value->type == FWP_RANGE_TYPE) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "avoid error (FWP_RANGE_TYPE)\"");
    }
    else if (value->type == FWP_DATA_TYPE_MAX) {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "avoid error (FWP_DATA_TYPE_MAX)\"");
    }
    else {
        MSVCRT$sprintf_s(buffer2, sizeof(buffer2), "Unknown type\"");
    }
    writeToFile(file, buffer2);
}

void queryAllWFPFilters() {
    HANDLE hEngine = NULL;
    DWORD result = 0;
    HANDLE enumHandle = NULL;
    FWPM_FILTER0** filters = NULL;
    UINT32 numFilters = 0;

    // Open the WFP engine
    result = _FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        err("FwpmEngineOpen0 failed: %u\n", result);
        return;
    }

    // Create an enumeration handle for filters
    result = _FwpmFilterCreateEnumHandle0(hEngine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        err("FwpmFilterCreateEnumHandle0 failed: %u\n", result);
        _FwpmEngineClose0(hEngine);
        return;
    }

    // Open file for output
    HANDLE file = openFile("C:\\Temp\\WFP_Filter_Output.txt");
    
    if (!file) {
        _FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
        _FwpmEngineClose0(hEngine);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Start WFP filter enumeration");
    int i = 0;

    // Buffer for formatted output
    char buffer[1000]; // Declare the buffer for output strings

    while (TRUE) {
        i++;
        result = _FwpmFilterEnum0(hEngine, enumHandle, 1, &filters, &numFilters);
        if (result != ERROR_SUCCESS) {
            err("FwpmFilterEnum0 failed: %u\n", result);
            _FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
            _FwpmEngineClose0(hEngine);
            return;
        }
        if (numFilters == 0) {
            break;;
        }
        
        // #
        MSVCRT$sprintf_s(buffer, sizeof(buffer), "#%d,", i);
        writeToFile(file, buffer);

        // Filter ID:
        MSVCRT$sprintf_s(buffer, sizeof(buffer), "%llu,", filters[0]->filterId);
        writeToFile(file, buffer);

        // Filter Name
        if (filters[0]->displayData.name)
        {
            MSVCRT$sprintf_s(buffer, sizeof(buffer), "%ls,", filters[0]->displayData.name);
        }
        else {
            MSVCRT$sprintf_s(buffer, sizeof(buffer), "NULL,");
        }
        writeToFile(file, buffer);

        // Filter Description
        if (filters[0]->displayData.description) {
            MSVCRT$sprintf_s(buffer, sizeof(buffer), "%ls,", filters[0]->displayData.description);
        }
        else {
            MSVCRT$sprintf_s(buffer, sizeof(buffer), "NULL,");
        }
        writeToFile(file, buffer);

        // Filter Key
        //MSVCRT$sprintf_s(buffer, sizeof(buffer), "Filter Key: ");
        //writeToFile(file, buffer);
        printGUID(filters[0]->filterKey, file);

        // Flags
        MSVCRT$sprintf_s(buffer, sizeof(buffer), ",%s,", convertFilterFlags(filters[0]->flags));
        writeToFile(file, buffer);

        // Layer Key
        // MSVCRT$sprintf_s(buffer, sizeof(buffer), "Layer Key: ");
        // writeToFile(file, buffer);
        printGUID(filters[0]->layerKey, file);

        // Action Type
        MSVCRT$sprintf_s(buffer, sizeof(buffer), ",%s,", convertActionType(filters[0]->action.type));
        writeToFile(file, buffer);

        // Sublayer Key
        printGUID(filters[0]->subLayerKey, file);

        // Weight
        handleWeight(&filters[0]->weight, file);

        // Number of Conditions
        MSVCRT$sprintf_s(buffer, sizeof(buffer), ",%d,[", filters[0]->numFilterConditions);
        writeToFile(file, buffer);

        // Write conditions if present
        if (filters[0]->numFilterConditions > 0) {
            for (int j = 0; j < filters[0]->numFilterConditions; j++) {
                // Condition#
                // MSVCRT$sprintf_s(buffer, sizeof(buffer), "Condition %d:\n", j);
                // writeToFile(file, buffer);

                // Condition Field Key
                // MSVCRT$sprintf_s(buffer, sizeof(buffer), "Condition Field Key: ");
                // writeToFile(file, buffer);
                MSVCRT$sprintf_s(buffer, sizeof(buffer), "\"");
                writeToFile(file, buffer);
                printGUID(filters[0]->filterCondition[j].fieldKey, file);
                handleConditionMatchType(filters[0]->filterCondition[j].matchType, file);
                handleConditionValue(&filters[0]->filterCondition[j].conditionValue, file);\
                MSVCRT$sprintf_s(buffer, sizeof(buffer), ",");
                writeToFile(file, buffer);
            }
        }
        writeToFile(file, "]\n"); // Add space between filters

        // Free the memory for the current batch of filters
        _FwpmFreeMemory0((void**)&filters);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Done output");

    // Cleanup
    KERNEL32$CloseHandle(file);
    _FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
    _FwpmEngineClose0(hEngine);
}

void queryAllSublayers()
{
    HANDLE hEngine = NULL;
    DWORD result = 0;
    HANDLE enumHandle = NULL;
    FWPM_SUBLAYER0** sublayers = NULL;
    UINT32 numSublayers = 0;

    result = _FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        err("FwpmEngineOpen0 failed: %u\n", result);
        return;
    }

    result = _FwpmSubLayerCreateEnumHandle0(hEngine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        err("FwpmSubLayerCreateEnumHandle0 failed: %u\n", result);
        _FwpmEngineClose0(hEngine);
        return;
    }

     // Open file for output
    HANDLE file = openFile("C:\\Temp\\WFP_Sublayer_Output.txt");
    
    if (!file) {
        _FwpmSubLayerDestroyEnumHandle0(hEngine, enumHandle);
        _FwpmEngineClose0(hEngine);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Start WFP sublayer enumeration");
    int i = 0;

    // Buffer for formatted output
    char buffer[1000]; // Declare the buffer for output strings

    while (TRUE) {
        i++;
        result = _FwpmSubLayerEnum0(hEngine, enumHandle, 1, &sublayers, &numSublayers);
        if (result != ERROR_SUCCESS) {
            err("FwpmSubLayerEnum0 failed: %u\n", result);
            _FwpmSubLayerDestroyEnumHandle0(hEngine, enumHandle);
            _FwpmEngineClose0(hEngine);
            return;
        }
        if (numSublayers == 0) {
            break;;
        }

        // #
        MSVCRT$sprintf_s(buffer, sizeof(buffer), "#%d,", i);
        writeToFile(file, buffer);

        // SubLayer Key
        printGUID(sublayers[0]->subLayerKey, file);

        // Sublayer Name
        if (sublayers[0]->displayData.name) {
            MSVCRT$sprintf_s(buffer, sizeof(buffer), ",%ls,", sublayers[0]->displayData.name);
        }
        else {
            MSVCRT$sprintf_s(buffer, sizeof(buffer), "NULL,");
        }
        writeToFile(file, buffer);

        // Sublayer Description
        if (sublayers[0]->displayData.description) {
            MSVCRT$sprintf_s(buffer, sizeof(buffer), "%ls,", sublayers[0]->displayData.description);
        }
        else {
            MSVCRT$sprintf_s(buffer, sizeof(buffer), "NULL,");
        }
        
        writeToFile(file, buffer);

        // Flags
        if (sublayers[0]->flags == FWPM_SUBLAYER_FLAG_PERSISTENT)
        {
            MSVCRT$sprintf_s(buffer, sizeof(buffer), "FWPM_SUBLAYER_FLAG_PERSISTENT,");
        }
        else {
            MSVCRT$sprintf_s(buffer, sizeof(buffer), "No flag,");
        }
        writeToFile(file, buffer);

        // Weight
        MSVCRT$sprintf_s(buffer, sizeof(buffer), "%u", sublayers[0]->weight);
        writeToFile(file, buffer);

        writeToFile(file, "\n"); // Add space between sublayers

        _FwpmFreeMemory0((void**)&sublayers);
    }

    
    BeaconPrintf(CALLBACK_OUTPUT, "Done output");

    // Cleanup
    KERNEL32$CloseHandle(file);
    _FwpmSubLayerDestroyEnumHandle0(hEngine, enumHandle);
    _FwpmEngineClose0(hEngine);

}

void go(char * args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "abc");
    if (!InitFWPM()) {
        err("Init functions failed\n");
        return;
    }
    queryAllWFPFilters();
    queryAllSublayers();

}