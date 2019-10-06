#include "injector.h"

bool is_number(const std::string &s) {
	return !s.empty() && std::all_of(s.begin(), s.end(), ::isdigit);
}

int main(int argc, char** argv)
{
	Injector syringe;
	bool injected;

	std::string process;
	std::string dll;

	std::cout << "Enter DLL name:\n";
	std::getline(std::cin, dll);

	std::fstream bin(dll, std::ios::in | std::ios_base::binary);
	if (!bin) {
		std::cerr << "[!]DLL file does NOT exist!" << "\n";
		return false;
		exit(1);
	}

	std::cout << "Enter process name or pid:\n";
	std::getline(std::cin, process);
	if (is_number(process)) {
		uint32_t pid = std::stoi(process);
		std::cout << "[+]Input Process ID: " << pid << "\n";
		injected = syringe.inject(pid, dll);
	}
	else {
		injected = syringe.inject(syringe.get_pid(process), dll);
	}

	if (injected) {
		std::cout << "[+]DLL Successfully Injected" << "\n";
	}
	else {
		std::cout << "[!]DLL Failed to Inject" << "\n"; 
		exit(1);
	}

	return 0;
}