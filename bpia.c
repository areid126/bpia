#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <psapi.h>

#pragma comment (lib, "fwpuclnt.lib")

#define EXIT_ON_ERROR(fnName) \
   if (result != ERROR_SUCCESS) \
   { \
      printf(#fnName " = 0x%08lX\n", result); \
      goto CLEANUP; \
   }


// Struct to store a linked list of the executables
typedef struct ProcessLinkedList {
    TCHAR exePath[MAX_PATH];
    struct ProcessLinkedList* nxtPath;
} ProcessList;

// Function declarations
TCHAR* get_file_name(TCHAR* path);
WCHAR* get_filter_name(TCHAR* path);
DWORD get_all_filters();
DWORD get_layer_filters(GUID* layer);
ProcessList* create_list_node(ProcessList* prev, ProcessList* next, TCHAR* content, DWORD size);
WCHAR* format_path(TCHAR* path);
void configure_filter_conditions(FWPM_FILTER_CONDITION* cond, FWP_BYTE_BLOB* appID);
DWORD block_process(TCHAR* path);
DWORD unblock_process_by_layer(HANDLE hEngine, TCHAR* path, GUID layer);
DWORD unblock_process(TCHAR* path);
void get_process_executable(DWORD processID, ProcessList* head);
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
DWORD filter_process(ProcessList* head);


DWORD wmain(int argc, wchar_t* argv[])
{
    int res = 0;

    // The user wants to print all current filters
    if (argc > 1 && wcscmp(argv[1], L"-f") == 0) {

        // Print all filters
        if (argc == 2) get_all_filters();
        
        // Print only filters on the specified layer
        else if (argc == 3) {

            GUID layer;

            // If the user wants to print all the filters on the IPv4 layer used by this program
            if(wcscmp(argv[2], L"default_v4") == 0)
                layer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
            
            // If the user wants to print all the filters on the IPv6 layer used by this program
            else if(wcscmp(argv[2], L"default_v6") == 0) 
                layer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
                
            // If the user entered any other layer name
            else {
                printf("Error: layer must be 'default_v4' or 'default_v6'\n");
                return 1;
            }

            get_layer_filters(&layer);
            
        }

        // There are too many arguments
        else {
            printf("Error: unsupported argument\n");
            return 1;
        }

    }
    // The user would like to apply a filter
    else {

        // Allocate the head of the list of all processes/executables
        ProcessList* head = malloc(sizeof(ProcessList));
        memset(head, 0, sizeof(ProcessList));

        // The user would like to enumerate all apps
        if (argc == 1) {
            // Enumerate all windows (pass the list of enumerated windows as a parameter)
            EnumWindows(EnumWindowsProc, (LPARAM)head);

        }
        // The user would like to enumerate all processes
        else if (argc == 2 && wcscmp(argv[1], L"-p") == 0) {

            // Get the list of process identifiers
            DWORD aProcesses[1024], cbNeeded, cProcesses;

            if (!EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ))
            {
                printf("Error: Unable to get processes\n");
                return 1;
            }

            // Calculate how many process identifiers were returned
            cProcesses = cbNeeded / sizeof(DWORD);

            // Get the executables for each process
            for (unsigned int i = 0; i < cProcesses; i++ )
                if(aProcesses[i] != 0) get_process_executable(aProcesses[i], head);
                
        } 
        else {
            printf("Error: unsupported arguments\n");
            return 1;
        }

        // Run the usual code for the individual executables here
        res = filter_process(head);

        // Deallocate the linked list of all the processes
        ProcessList* temp;
        while(head != 0) {
            temp = head->nxtPath; // Store the next node
            free(head); // Deallocate the current head
            head = temp; // Reassign the head
        }
    }

    return res; // Return the result of whether performing the opperation was successful
}

// Support functions

// Gets the name of the executable from the absolute path to the executable
// Returned pointer is contained inside the greater path
TCHAR* get_file_name(TCHAR* path) {
    
    // Get just the executable name
    DWORD i;

    // Find the executable name from before the final '\'
    for (i = MAX_PATH - 1; i >= 0; i--) 
        if (path[i] == TEXT('\\')) break;
        else if (i == 0) return path; // If there is no '\' then return the full path

    // Return the found index
    return path + i + 1;
}

// Gets the name of the filter for blocking traffic from that specific program
// Returns a pointer to the new name. This pointer needs to be freed once finished with
WCHAR* get_filter_name(TCHAR* path) {

    WCHAR* str = L"BPIA Block ";
    WCHAR* strEnd = L" from accessing the internet";
    TCHAR* name = get_file_name(path);
    DWORD len = wcslen(str) + strlen(name) + wcslen(strEnd) + 1, strLen = wcslen(str);

    // Allocate the new string
    WCHAR* filter_name = malloc(len * sizeof(WCHAR)); 
    memset(filter_name, 0, len * sizeof(WCHAR));

    wcscat_s(filter_name, len, str); // Concatenate the start string

    for (unsigned int i = 0; i < strlen(name) + 1; i++) {
        // Set the chars in the combined name as well
        filter_name[strLen + i] = name[i];

        if(name[i] == 0) break; // Stop looping after the end
    }

    wcscat_s(filter_name, len, strEnd); // Concatenate the end string
    return filter_name; // Return the created string
}

// Create a new node within a linked list
// Returns 0 on fail and a pointer to the created node on success
ProcessList* create_list_node(ProcessList* prev, ProcessList* next, TCHAR* content, DWORD size) {
    if(size > MAX_PATH) return 0; // Make sure the content will fit
    
    // Create the new node
    ProcessList* node = malloc(sizeof(ProcessList));
    memset(node, 0, sizeof(ProcessList));

    // Assign fields in the node
    strcpy_s(node->exePath, MAX_PATH, content);
    if(next != NULL) node->nxtPath = next;
    if(prev != NULL) prev->nxtPath = node;

    // Return a pointer to the node
    return node;
}

// Duplicates all '\' in a path
// Returns a pointer to the new path. This pointer must be deallocated once finished with
WCHAR* format_path(TCHAR* path) {
    
    int i = 0;

    // Kinda hacky code for duplicating the '\' in the string
    DWORD count = 0;
    
    for (i = 0; i < MAX_PATH; i++) {
        if(path[i] == '\\') count++; // Count all backslashes
        if(path[i] == 0) break; // Stop looping after the end
    }

    // Allocate the new string
    WCHAR* fileName = malloc((i + 1 + count) * sizeof(WCHAR)); 
    DWORD j = 0; // Position in the copied word
    
    // Copy the string over
    for(i = 0; i < MAX_PATH; i++) {
        if(path[i] == '\\') {
            fileName[j++] = '\\';
            fileName[j++] = '\\';
        }
        else fileName[j++] = path[i];
        
        // Break at the end of the string
        if(path[i] == 0) break;
    }

    // Return the newly allocated string
    return fileName;
}

// Configures the condition to filter an application
void configure_filter_conditions(FWPM_FILTER_CONDITION* cond, FWP_BYTE_BLOB* appID) {

    // Specify the filter fields
    cond->fieldKey = FWPM_CONDITION_ALE_APP_ID; // The field that the filter applies to
    cond->matchType = FWP_MATCH_EQUAL;
    cond->conditionValue.type = FWP_BYTE_BLOB_TYPE;
    cond->conditionValue.byteBlob = appID;
}

// Blocks a specific program based on the path to its executable
DWORD block_process(TCHAR* path) {
    
    // Open a handle to the WFP engine
    HANDLE hEngine;
    FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);

    // Set up the filter
    FWPM_FILTER filter;   
    memset(&filter, 0, sizeof(filter)); // Set the filter to be '0'
    WCHAR* filterName = get_filter_name(path); // Get the name for the filter for that specific process
    filter.displayData.name = filterName;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_BLOCK;

    // Get the ID of the application to block
    FWP_BYTE_BLOB* appId = NULL;
    WCHAR* filename = format_path(path);
    FwpmGetAppIdFromFileName(filename, &appId);

    // Specify the filter fields
    FWPM_FILTER_CONDITION cond;
    configure_filter_conditions(&cond, appId);
    filter.filterCondition = &cond;
    filter.numFilterConditions = 1;

    // Add the filter to block IPv4 and IPv6 traffic
    DWORD res = FwpmFilterAdd(hEngine, &filter, NULL, NULL);
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;   // IPv6
    DWORD res2 = FwpmFilterAdd(hEngine, &filter, NULL, NULL);

    if(res == ERROR_SUCCESS && res2 == ERROR_SUCCESS) printf("Successfully added the filter\n");
    else printf("Error: Failed to add the filter\n");

    // Free memory
    FwpmFreeMemory((void**)&appId);
    FwpmEngineClose(hEngine);
    free(filename); // Free the allocated file name
    free(filterName); // Free the allocated filter name

    return 0;
}

// Unblock a process from accessing the internet
DWORD unblock_process_by_layer(HANDLE hEngine, TCHAR* path, GUID layer) {

    // Get the key of the filter
    DWORD result = ERROR_SUCCESS;
    FWP_BYTE_BLOB* appBlob = NULL;
    FWPM_FILTER_ENUM_TEMPLATE0 enumTempl;
    HANDLE enumHandle = NULL;

    // Set the enum for the conditions to be all 0s
    memset(&enumTempl, 0, sizeof(enumTempl));

    // Get the program to unfilter
    WCHAR *filename = format_path(path);
    FWP_BYTE_BLOB* appId;
    FwpmGetAppIdFromFileName(filename, &appId);
    FWPM_FILTER_CONDITION cond; // Specify the filter fields
    configure_filter_conditions(&cond, appId);

    // Set the enum conditions
    enumTempl.numFilterConditions = 1;
    enumTempl.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED; // Only get filters that completely contain the conditions
    enumTempl.filterCondition = &cond; // Set the conditions of the filter to be the same as for the applied filter
    enumTempl.flags = FWP_FILTER_ENUM_FLAG_BEST_TERMINATING_MATCH; // Only return the best match
    enumTempl.actionMask = FWP_ACTION_BLOCK ^ FWP_ACTION_FLAG_TERMINATING; // Get only the filters that block
    enumTempl.layerKey = layer; // Only get filters on the desired layer

    // Create the filter handler
    result = FwpmFilterCreateEnumHandle0(hEngine, &enumTempl, &enumHandle);
    EXIT_ON_ERROR(FwpmFilterCreateEnumHandle0);

    UINT32 numFilters = 0;
    FWPM_FILTER0** filters = 0;

    // Get the filters that match the query
    result = FwpmFilterEnum0(hEngine, enumHandle, 1, &filters, &numFilters);
    EXIT_ON_ERROR(FwpmFilterEnum0);

    // Get the name of the filter it delete
    WCHAR* filterName = get_filter_name(path);


    // Only one result will be returned
    if (result == ERROR_SUCCESS && numFilters == 1 && wcscmp((filters[0])->displayData.name, filterName) == 0) {

        printf("Found filter '%ws'. Do you want to delete this filter [Y-N]?\n", (filters[0])->displayData.name);
        
        // Get the user's response
        char buff[11]; // Allocate a buffer to store the integer
        memset(buff, 0, 11); // Clear the buffer
        fgets(buff, 11, stdin);
        char ans = buff[0];
        
        // If the user said yes delete the filter
        if (ans == 'Y' || ans == 'y') {

            // Delete the filter
            result = FwpmFilterDeleteByKey0(hEngine, &(filters[0]->filterKey));
            EXIT_ON_ERROR(FwpmFilterDeleteByKey0);
            printf("Successfully removed the filter\n");
        }
        // Otherwise do not delete the filter
        else {
            printf("Filter was not deleted\n");
        } 
    }

CLEANUP:
    FwpmFreeMemory0((void**)&appBlob);

    if (result != ERROR_SUCCESS)
    {
        printf("Error: %lx\n", result);
    }

    // Free up resources
    FwpmFreeMemory((void**)&filters);
    return 0;
}

// Unblocks the process for both IPv4 and IPv6 communication
DWORD unblock_process(TCHAR* path) {
    
    // Open a handle to the WFP engine
    HANDLE hEngine;
    FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);

    // Delete the IPv4 and IPv6 versions of the filter
    printf("Checking the IPv4 filters\n");
    DWORD res = unblock_process_by_layer(hEngine, path, FWPM_LAYER_ALE_AUTH_CONNECT_V4);
    printf("Checking the IPv6 filters\n");
    res = unblock_process_by_layer(hEngine, path, FWPM_LAYER_ALE_AUTH_CONNECT_V6);

    // Close the handle to the filtering platform
    FwpmEngineClose(hEngine);

    return res;
}

// Gets the executable responsible for a specific process
void get_process_executable(DWORD processID, ProcessList* head) {
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    TCHAR* name = szProcessName; // Take the full word

    // Get a handle to the process.
    HANDLE hProcess = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processID );

    // Get the process name.
    if (NULL != hProcess )
    {
        DWORD len = sizeof(szProcessName)/sizeof(TCHAR);
        QueryFullProcessImageName(hProcess, 0, szProcessName, &len);

        // Store the process in the process list (if it is not already there)
        ProcessList* prevNode = head;
        head = head->nxtPath; // Skip the first node

        // Get the short name
        TCHAR* headName;
        name = get_file_name(szProcessName);
        // Indicate whether the node was successfully created
        int insrtd = 0;

        // If the head has no next this is the first window
        if(head == 0) create_list_node(prevNode, NULL, szProcessName, len);
        else {

            // Loop through all the nodes in the array to find the correct position to insert at
            while(head != 0) {

                headName = get_file_name(head->exePath); // Get the exponential name for the process

                // Stop looping if the executable is already in the array
                if(_stricmp(headName, name) == 0) {
                    insrtd = 1; // Set it as having been inserted
                    break;
                }
                // If the second string comes first (the process name)
                else if (_stricmp(headName, name) > 0) {

                    // Create the new node
                    create_list_node(prevNode, head, szProcessName, len);

                    insrtd = 1; // Set it as having been inserted
                    break; // Stop looping as the path has been inserted
                }

                // If the first string comes first then move to the next node
                prevNode = head;
                head = head->nxtPath;    
            }

            // If it finishes the loop without having been inserted then it is inserted at the end
            if (!insrtd) {
                // Create the new node
                create_list_node(prevNode, NULL, szProcessName, len);
            }

        }
    }

    // Release the handle to the process.
    CloseHandle( hProcess );
}

// Callback function for enumerating all the current windows
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    // Get the process associated with the header
    DWORD processID = 0;
    DWORD res = GetWindowThreadProcessId(hwnd, &processID);
    
    // Get the process associated with the window if it is visible
    if (res != 0 && IsWindowVisible(hwnd)) 
        get_process_executable(processID, (ProcessList*) lParam);

    return 1;
}

// Function for handling applying/removing filters from a process
DWORD filter_process(ProcessList* head) {
    DWORD i = 1;

    printf("Please select an application to filter from the list below:\n");

    TCHAR* name;
    ProcessList* node = head->nxtPath;

    // Print the enumerated list to the user to allow them to select a specific application to block
    while(node != 0) {

        name = get_file_name(node->exePath);

        printf("[%lu] %s\n", i, name); // Print the name and number of the application

        i++; // Increment the number of things printed
        node = node->nxtPath; // Get the next node in the list
    }

    printf("Enter [1-%lu] to select the application to filter\n", i - 1);

    // Get the user's choice of application
    DWORD selection;
    char buff[11]; // Allocate a buffer to store the integer
    memset(buff, 0, 11); // Clear the buffer
    fgets(buff, 11, stdin); // Read 10 characters from stdin (as any more will be too big for an integer)
    int res = sscanf_s(buff, "%ld", &selection);


    // If there is an error reading input then print it
    if(res == EOF) {
        printf("Error: unable to receive input\n");
        return 1;
    }

    if(res == 0) {
        buff[strlen(buff) - 1] = 0; // Remove \n
        printf("Error: '%s' is not a valid option\n", buff);
        return 1;
    }

    if(selection < 1 || selection >= i) {
        printf("Error: %ld is out of range\n", selection);
        return 1;
    }

    ProcessList* process = head;

    // Get the specific application and print it to the user
    for(DWORD k = 0; k < selection; k++) process = process->nxtPath;

    TCHAR* processName = get_file_name(process->exePath);

    // Inform the user of their choice
    printf("You have selected %s\n", processName);
    printf("Would you like to apply [A] a filter or remove [R] a filter [A-R]?\n");

    // Get the user's response
    memset(buff, 0, 11); // Clear the buffer
    fgets(buff, 11, stdin);
    char ans = buff[0];
    
    if (ans == 'A' || ans == 'a') {
        printf("Block process selected\n");
        block_process(process->exePath);
    }
    else if (ans == 'R' || ans == 'r') {
        printf("Unblock process selected\n");
        unblock_process(process->exePath);
    } 
    else if (ans == '\n' || ans == '\0') {
        printf("Error: no option selected\n");
    }
    else {
        printf("Error: %c is not a valid option\n", ans);
        return 1;
    }

    return 0;
}

// Get all the filters at a specific layer
DWORD get_layer_filters(GUID* layer) {
    // Open a session to the filter engine
    HANDLE engineHandle = 0;

    // Use dynamic sessions 
    FWPM_SESSION0 session;
    memset(&session, 0, sizeof(session));
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    UINT32 numFilters = 0;
    FWPM_FILTER0** filters = 0;
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engineHandle);
    EXIT_ON_ERROR(FwpmEngineOpen0);
    FWPM_FILTER_ENUM_TEMPLATE0 enumTempl;
    HANDLE enumHandle = NULL;

    // Set the enum for the conditions to be all 0s
    memset(&enumTempl, 0, sizeof(enumTempl));
    // Set the layer key
    enumTempl.layerKey = *layer;
    // Do not match any conditions
    enumTempl.numFilterConditions = 0;
    // Get all filters regardless of action
    enumTempl.actionMask = 0xFFFFFFFF;

    // Create the filter handler
    result = FwpmFilterCreateEnumHandle0( engineHandle, &enumTempl, &enumHandle );
    EXIT_ON_ERROR(FwpmFilterCreateEnumHandle0);

    // Get the filters that match the query
    result = FwpmFilterEnum0( engineHandle, enumHandle, INFINITE, &filters, &numFilters );
    EXIT_ON_ERROR(FwpmFilterEnum0);


CLEANUP:  
    if (result != ERROR_SUCCESS)
    {
        printf("Error: %lx\n", result);
    }
    else
    {
        for (UINT32 i = 0; i < numFilters; i++) 
            printf("[%d] %-40ws\n", i, filters[i]->displayData.name);
    }

    FwpmFreeMemory((void**)&filters);
    FwpmFilterDestroyEnumHandle0(engineHandle, enumHandle);

    return result;
}

// Gets every filter across every layer
DWORD get_all_filters() {

    // open a handle to the WFP engine
    HANDLE hEngine;
    FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
 
    // Create an enumeration handle
    HANDLE hEnum;
    FwpmFilterCreateEnumHandle(hEngine, NULL, &hEnum);
 
    // Enumerate every filter
    UINT32 count;
    FWPM_FILTER** filters;
    FwpmFilterEnum(hEngine, hEnum, 8192, &filters, &count); 

    for (UINT32 i = 0; i < count; i++) 
        printf("[%d] %-40ws\n", i, filters[i]->displayData.name);
    
    
    // Free memory allocated by FwpmFilterEnum
    FwpmFreeMemory((void**)&filters);
    // Close enumeration handle
    FwpmFilterDestroyEnumHandle(hEngine, hEnum);
    // Close engine handle
    FwpmEngineClose(hEngine);

    return 0;
}

