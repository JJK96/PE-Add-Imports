#include "PEFile.h"

int main(int argc, char* argv[]) {
	// Open the input file
	PEFile pe(argv[0]);

	pe.addImport(argv[1], &argv[3], 1);
	
	// Add a new section named ".at4re" with size "0x1000" byte
	pe.addSection(".at4re", 0x1000, false);
	
	// Save the modified file
	pe.saveToFile(argv[2]);
}
