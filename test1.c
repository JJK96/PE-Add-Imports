#include <stdio.h>
#include <windows.h>

DWORD LoadFileIntoMemory(char *pPath, BYTE **pFileData, DWORD *pdwFileSize)
{
	HANDLE hFile = NULL;
	DWORD dwFileSize = 0;
	BYTE *pFileDataBuffer = NULL;
	DWORD dwBytesRead = 0;

	// open file
	hFile = CreateFile(pPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		return 1;
	}

	// calculate file size
	dwFileSize = GetFileSize(hFile, NULL);

	// allocate buffer
	pFileDataBuffer = (BYTE*)malloc(dwFileSize);
	if(pFileDataBuffer == NULL)
	{
		return 1;
	}

	// read file contents
	if(ReadFile(hFile, pFileDataBuffer, dwFileSize, &dwBytesRead, NULL) == 0)
	{
		return 1;
	}

	// verify byte count
	if(dwBytesRead != dwFileSize)
	{
		return 1;
	}

	// close file handle
	CloseHandle(hFile);

	// store values
	*pFileData = pFileDataBuffer;
	*pdwFileSize = dwFileSize;

	return 0;
}

DWORD WriteToFile(char *pPath, BYTE *pFileData, DWORD dwOrigFileSize, DWORD dwNewDataFilePosition, BYTE *pNewImportDirectory, DWORD dwNewImportDirectorySize, char *pDllName, BYTE *pImportLookupTable, DWORD dwImportLookupTableSize, DWORD dwPaddingBytes)
{
	HANDLE hFile = NULL;
	DWORD dwBytesWritten = 0;
	BYTE bPaddingByte = 0;

	// create file
	hFile = CreateFile(pPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		return 1;
	}

	// write original EXE data
	if(WriteFile(hFile, (void *)pFileData, dwNewDataFilePosition, &dwBytesWritten, NULL) == 0)
	{
		return 1;
	}

	// write new import directory
	if(WriteFile(hFile, (void *)pNewImportDirectory, dwNewImportDirectorySize, &dwBytesWritten, NULL) == 0)
	{
		return 1;
	}

	// write DLL name
	if(WriteFile(hFile, (void *)pDllName, (DWORD)(strlen(pDllName) + 1), &dwBytesWritten, NULL) == 0)
	{
		return 1;
	}

	// write import lookup table
	if(WriteFile(hFile, (void *)pImportLookupTable, dwImportLookupTableSize, &dwBytesWritten, NULL) == 0)
	{
		return 1;
	}

	// write import lookup table
	if(WriteFile(hFile, (void*)pImportLookupTable, dwImportLookupTableSize, &dwBytesWritten, NULL) == 0)
	{
		return 1;
	}

	// write section padding
	for(DWORD i = 0; i < dwPaddingBytes; i++)
	{
		if(WriteFile(hFile, (void*)&bPaddingByte, 1, &dwBytesWritten, NULL) == 0)
		{
			return 1;
		}
	}

	// write original appended data (debug symbols, installation data, etc)
	if(WriteFile(hFile, (void *)(pFileData + dwNewDataFilePosition), dwOrigFileSize - dwNewDataFilePosition, &dwBytesWritten, NULL) == 0)
	{
		return 1;
	}

	// close file handle
	CloseHandle(hFile);

	return 0;
}

BYTE *VirtualAddressToFilePtr(BYTE *pFileData, IMAGE_NT_HEADERS32 *pImageNtHeader, DWORD dwVirtualAddress)
{
	IMAGE_SECTION_HEADER *pCurrSectionHeader = NULL;
	BYTE *pFilePtr = NULL;
	DWORD dwSectionDataLength = 0;

	// loop through all sections
	for(DWORD i = 0; i < pImageNtHeader->FileHeader.NumberOfSections; i++)
	{
		// get current section header
		pCurrSectionHeader = (IMAGE_SECTION_HEADER *)((BYTE*)&pImageNtHeader->OptionalHeader + pImageNtHeader->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if(pCurrSectionHeader->SizeOfRawData != 0)
		{
			// calculate section data length (on disk)
			dwSectionDataLength = pCurrSectionHeader->SizeOfRawData;
			if(dwVirtualAddress >= pCurrSectionHeader->VirtualAddress && dwVirtualAddress < (pCurrSectionHeader->VirtualAddress + dwSectionDataLength))
			{
				pFilePtr = pFileData;
				pFilePtr += pCurrSectionHeader->PointerToRawData;
				pFilePtr += (dwVirtualAddress - pCurrSectionHeader->VirtualAddress);

				return pFilePtr;
			}
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	DWORD dwFileSize = 0;
	BYTE *pFileData = NULL;
	IMAGE_DOS_HEADER *pImageDosHeader = NULL;
	IMAGE_NT_HEADERS32 *pImageNtHeader = NULL;
	IMAGE_NT_HEADERS64 *pImageNtHeader64 = NULL;
	IMAGE_DATA_DIRECTORY *pImageDataDirectory = NULL;
	char *pInputFilePath = NULL;
	char *pDllName = NULL;
	char szOutputFilePath[512];
	IMAGE_THUNK_DATA32 ImportLookupTable32[2];
	IMAGE_THUNK_DATA64 ImportLookupTable64[2];
	DWORD dwTotalAddedSize = 0;
	IMAGE_IMPORT_DESCRIPTOR *pImageImportDescriptor = NULL;
	BYTE *pImportBaseAddr = NULL;
	DWORD dwCurrImportBlockOffset = 0;
	IMAGE_SECTION_HEADER *pCurrSectionHeader = NULL;
	IMAGE_SECTION_HEADER *pLastSectionHeader = NULL;
	DWORD dwNewDataVirtualAddress = 0;
	DWORD dwModuleCount = 0;
	DWORD dwNewDataFilePosition = 0;
	IMAGE_IMPORT_DESCRIPTOR NewDllImportDescriptors[2];
	DWORD dwOrigImportSize = 0;
	DWORD dwNewImportDirectorySize = 0;
	BYTE *pNewImportDirectory = NULL;
	BYTE *pCopyImportPtr = NULL;
	DWORD dwFileAlignment = 0;
	DWORD dwPaddingBytes = 0;
	BYTE *pImportLookupTable = NULL;
	DWORD dwImportLookupTableSize = 0;

	printf("AddExeImport - www.x86matthew.com\n\n");

	if(argc != 3)
	{
		printf("Usage: %s [input_exe_path] [add_dll_name]\n\n", argv[0]);

		return 1;
	}

	// get cmd param
	pInputFilePath = argv[1];
	pDllName = argv[2];

	printf("Opening EXE: '%s'...\n", pInputFilePath);

	// load dll into memory
	if(LoadFileIntoMemory(pInputFilePath, &pFileData, &dwFileSize) != 0)
	{
		printf("Error: Failed to load EXE into memory\n");

		return 1;
	}

	// get dos header
	pImageDosHeader = (IMAGE_DOS_HEADER *)pFileData;
	if(pImageDosHeader->e_magic != 0x5A4D)
	{
		printf("Error: Invalid EXE\n");

		free(pFileData);
		return 1;
	}

	// get nt header
	pImageNtHeader = (IMAGE_NT_HEADERS32 *)(pFileData + pImageDosHeader->e_lfanew);
	if(pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("Error: Invalid EXE\n");

		free(pFileData);
		return 1;
	}

	// check exe type
	if(pImageNtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		// 64-bit
		printf("64-bit EXE detected\n");
		pImageNtHeader64 = (IMAGE_NT_HEADERS64 *)pImageNtHeader;
		pImageDataDirectory = pImageNtHeader64->OptionalHeader.DataDirectory;
	}
	else if(pImageNtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		// 32-bit
		printf("32-bit EXE detected\n");
		pImageNtHeader64 = NULL;
		pImageDataDirectory = pImageNtHeader->OptionalHeader.DataDirectory;
	}
	else
	{
		printf("Error: Invalid EXE\n");

		free(pFileData);
		return 1;
	}

	// find import table
	pImportBaseAddr = VirtualAddressToFilePtr(pFileData, pImageNtHeader, pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if(pImportBaseAddr == NULL)
	{
		printf("Error: Invalid EXE\n");

		free(pFileData);
		return 1;
	}

	// find last section in file (this should be the last entry in the list but this is not necessarily the case)
	for(DWORD i = 0; i < pImageNtHeader->FileHeader.NumberOfSections; i++)
	{
		// get current section header
		pCurrSectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)&pImageNtHeader->OptionalHeader + pImageNtHeader->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));

		if(pLastSectionHeader == NULL)
		{
			// set initial value
			pLastSectionHeader = pCurrSectionHeader;
		}
		else
		{
			// check if this section is the last entry so far
			if(pCurrSectionHeader->PointerToRawData > pLastSectionHeader->PointerToRawData)
			{
				// store current value
				pLastSectionHeader = pCurrSectionHeader;
			}
		}
	}

	// ensure the last section was found
	if(pLastSectionHeader == NULL)
	{
		printf("Error: Invalid EXE\n");

		free(pFileData);
		return 1;
	}

	// store positions of the end of the current EXE contents (virtual address + file position)
	dwNewDataVirtualAddress = pLastSectionHeader->VirtualAddress + pLastSectionHeader->SizeOfRawData;
	dwNewDataFilePosition = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;

	// check if the exe already contains imports
	if(pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
	{
		// calculate number of existing imported modules
		for(;;)
		{
			pImageImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(pImportBaseAddr + dwCurrImportBlockOffset);
			if(pImageImportDescriptor->Name == 0)
			{
				// finished
				break;
			}

			// increase counter
			dwModuleCount++;

			// update import block offset
			dwCurrImportBlockOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		}
	}

	printf("Adding '%s' to import table...\n", pDllName);

	// allocate memory for new (enlarged) import table
	dwOrigImportSize = dwModuleCount * sizeof(IMAGE_IMPORT_DESCRIPTOR);
	dwNewImportDirectorySize = dwOrigImportSize + sizeof(NewDllImportDescriptors);
	pNewImportDirectory = (BYTE*)malloc(dwNewImportDirectorySize);
	if(pNewImportDirectory == NULL)
	{
		printf("Error: Failed to allocate memory\n");

		free(pFileData);
		return 1;
	}

	// set import descriptor values for new dll
	NewDllImportDescriptors[0].Name = dwNewDataVirtualAddress + dwNewImportDirectorySize;
	NewDllImportDescriptors[0].OriginalFirstThunk = NewDllImportDescriptors[0].Name + (DWORD)strlen(pDllName) + 1;
	NewDllImportDescriptors[0].FirstThunk = NewDllImportDescriptors[0].OriginalFirstThunk;
	if(pImageNtHeader64 == NULL)
	{
		// 32-bit
		NewDllImportDescriptors[0].FirstThunk += sizeof(ImportLookupTable32);
	}
	else
	{
		// 64-bit
		NewDllImportDescriptors[0].FirstThunk += sizeof(ImportLookupTable64);
	}
	NewDllImportDescriptors[0].TimeDateStamp = 0;
	NewDllImportDescriptors[0].ForwarderChain = 0;

	// end of import descriptor chain
	NewDllImportDescriptors[1].OriginalFirstThunk = 0;
	NewDllImportDescriptors[1].TimeDateStamp = 0;
	NewDllImportDescriptors[1].ForwarderChain = 0;
	NewDllImportDescriptors[1].Name = 0;
	NewDllImportDescriptors[1].FirstThunk = 0;

	// copy original imports to the buffer
	pCopyImportPtr = pNewImportDirectory;
	if(dwModuleCount != 0)
	{
		memcpy(pNewImportDirectory, pImportBaseAddr, dwOrigImportSize);
		pCopyImportPtr += dwOrigImportSize;
	}

	// append the new imported module to the end of the list
	memcpy((void*)pCopyImportPtr, (void*)&NewDllImportDescriptors, sizeof(NewDllImportDescriptors));

	// initialise import lookup table for the new DLL (1 import - ordinal #1) - 32-bit
	ImportLookupTable32[0].u1.Ordinal = 0x80000001;
	ImportLookupTable32[1].u1.Ordinal = 0;

	// initialise import lookup table for the new DLL (1 import - ordinal #1) - 64-bit
	ImportLookupTable64[0].u1.Ordinal = 0x8000000000000001;
	ImportLookupTable64[1].u1.Ordinal = 0;

	// update IAT directory position
	pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = dwNewDataVirtualAddress;
	pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = dwNewImportDirectorySize;

	// calculate total length of additional data to append
	dwTotalAddedSize = dwNewImportDirectorySize;
	dwTotalAddedSize += (DWORD)strlen(pDllName) + 1;
	if(pImageNtHeader64 == NULL)
	{
		// 32-bit
		dwTotalAddedSize += (sizeof(ImportLookupTable32) * 2);
	}
	else
	{
		// 64-bit
		dwTotalAddedSize += (sizeof(ImportLookupTable64) * 2);
	}

	// get file alignment value
	if(pImageNtHeader64 == NULL)
	{
		// 32-bit
		dwFileAlignment = pImageNtHeader->OptionalHeader.FileAlignment;
	}
	else
	{
		// 64-bit
		dwFileAlignment = pImageNtHeader64->OptionalHeader.FileAlignment;
	}

	// calculate number of bytes to pad (section data in file must be aligned)
	dwPaddingBytes = dwFileAlignment - (dwTotalAddedSize % dwFileAlignment);
	if(dwPaddingBytes == dwFileAlignment)
	{
		dwPaddingBytes = 0;
	}
	dwTotalAddedSize += dwPaddingBytes;

	// the last section must have read/write permissions at minimum to allow the loader to store the resolved IAT value
	pLastSectionHeader->Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	pLastSectionHeader->SizeOfRawData += dwTotalAddedSize;
	pLastSectionHeader->Misc.VirtualSize += dwTotalAddedSize;
	if(pImageNtHeader64 == NULL)
	{
		// 32-bit
		pImageNtHeader->OptionalHeader.SizeOfImage += dwTotalAddedSize;
	}
	else
	{
		// 64-bit
		pImageNtHeader64->OptionalHeader.SizeOfImage += dwTotalAddedSize;
	}

	// check if debug symbols are currently stored at the end of the exe
	if(pImageNtHeader->FileHeader.PointerToSymbolTable == dwNewDataFilePosition)
	{
		// adjust debug symbol ptr
		pImageNtHeader->FileHeader.PointerToSymbolTable += dwTotalAddedSize;
	}

	// get import lookup table values
	if(pImageNtHeader64 == NULL)
	{
		// 32-bit
		pImportLookupTable = (BYTE*)&ImportLookupTable32[0];
		dwImportLookupTableSize = sizeof(ImportLookupTable32);
	}
	else
	{
		// 64-bit
		pImportLookupTable = (BYTE*)&ImportLookupTable64[0];
		dwImportLookupTableSize = sizeof(ImportLookupTable64);
	}

	// write new exe to file
	memset(szOutputFilePath, 0, sizeof(szOutputFilePath));
	_snprintf_s(szOutputFilePath, sizeof(szOutputFilePath) - 1, "%s_modified.exe", pInputFilePath);
	printf("Writing new file to '%s'...\n", szOutputFilePath);
	if(WriteToFile(szOutputFilePath, pFileData, dwFileSize, dwNewDataFilePosition, pNewImportDirectory, dwNewImportDirectorySize, pDllName, pImportLookupTable, dwImportLookupTableSize, dwPaddingBytes) != 0)
	{
		printf("Error: Failed to write new EXE\n");

		free(pNewImportDirectory);
		free(pFileData);
		return 1;
	}

	printf("Finished\n");

	// free memory
	free(pNewImportDirectory);
	free(pFileData);

	return 0;
}

