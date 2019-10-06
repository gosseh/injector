#include "injector.h"

inline std::string unicode_to_string(const std::wstring& unicode_string)
{
	static std::wstring_convert<
		std::codecvt_utf8_utf16<int16_t>, int16_t
	> conversion;
	return conversion.to_bytes(reinterpret_cast<const int16_t*>(unicode_string.data()));
}

uint32_t Injector::get_pid(const std::string& processname)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 structprocsnapshot = { 0 };

	structprocsnapshot.dwSize = sizeof(PROCESSENTRY32);

	if (snap == INVALID_HANDLE_VALUE)return 0;
	if (Process32First(snap, &structprocsnapshot) == FALSE)return 0;

	while (Process32Next(snap, &structprocsnapshot))
	{
		if (!strcmp(structprocsnapshot.szExeFile, processname.c_str()))
		{
			CloseHandle(snap);
			std::cout << "[+]Process name is: " << processname << "\n[+]Process ID: " << structprocsnapshot.th32ProcessID << "\n";
			return structprocsnapshot.th32ProcessID;
		}
	}
	CloseHandle(snap);
	std::cerr << "[!]Unable to find Process ID\n";
	std::cerr << "[!]DLL Failed to Inject" << "\n";
	exit(1);
}

bool Injector::inject(const std::string& filename)
{
	return inject(m_processId, filename);
}

bool Injector::inject(const uint32_t pid, const std::string& filename) 
{
	m_processId = pid;
	if (!m_loadLibrary) {
		auto kernel32 = GetModuleHandleA("kernel32.dll");
		if (!kernel32) {
			return false;
		}

		m_loadLibrary = reinterpret_cast<uintptr_t>(GetProcAddress(kernel32, "LoadLibraryA"));
		if (!m_loadLibrary) {
			std::cerr << "[!]Fail to create Remote Thread\n";
			return false;
		}
	}

	/// check if the module is loaded
	auto temp_name = filename;
	const auto pos = temp_name.find_last_of("");
	if (pos != std::string::npos) {
		temp_name.erase(0, pos + 1);
	}

	if (parse_loaded_modules(pid).count(temp_name) != 0) {
		return false;
	}

	HANDLE process_handle = nullptr;
	void* data = nullptr;

	auto safe_exit = [&process_handle, &data] {
		if (process_handle) {
			if (data) {
				VirtualFreeEx(process_handle, data, 0, MEM_RELEASE);
				data = nullptr;
			}
			CloseHandle(process_handle);
			process_handle = nullptr;
		}
		return false;
	};

	/// try to open a process handle to the target process id
	process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (process_handle == INVALID_HANDLE_VALUE) {
		std::cerr << "[!]Fail to open target process!\n";
		return safe_exit();
	}
	std::cout << "[+]Opening Target Process...\n";

	/// calculate the length of the filename which gets written
	/// into the target process
	const auto data_size = filename.length() + 1;
	data = VirtualAllocEx(
		process_handle,
		nullptr,
		static_cast<DWORD>(data_size),
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	);
	if (!data) {
		std::cerr << "[!]Fail to allocate memory in Target Process.\n";
		return safe_exit();
	}
	std::cout << "[+]Allocating memory in Targer Process.\n";

	/// write the filename(absolute path) into the target process
	if (!WriteProcessMemory(
		process_handle,
		data,
		filename.data(),
		data_size,
		nullptr
	)) {
		std::cerr << "[!]Fail to write in Target Process memory.\n";
		return safe_exit();
	}
	std::cout << "[+]Creating Remote Thread in Target Process\n";

	/// create a thread in our target process and try to call
	/// their LoadLibraryA
	auto thread_handle = CreateRemoteThread(
		process_handle,
		nullptr,
		0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(m_loadLibrary),
		data,
		0,
		nullptr
	);
	if (thread_handle == INVALID_HANDLE_VALUE) {
		std::cerr << "[!]Fail to create Remote Thread\n";
		return safe_exit();
	}

	/// Wait unitl DllMain returns something
	WaitForSingleObject(thread_handle, INFINITE);
	
	/// free data
	return !safe_exit();
}

bool Injector::parse_process_modules()
{
	m_loadedModules = parse_loaded_modules();
	return !m_loadedModules.empty();
}

bool Injector::find_target_process(const std::string& process_name)
{
	for (const auto& kp : parse_running_proccesses()) {
		if (!process_name.compare(kp.first)) {
			m_processId = kp.second.th32ProcessID;
			return true;
		}
	}
	return false;
}

Injector::ModuleInfo Injector::parse_loaded_modules() const
{
	return std::move(parse_loaded_modules(m_processId));
}

void Injector::eject(const std::string& module_name)
{
	if (!m_loadedModules.count(module_name)) {
		return;
	}

	auto& mod_data = m_loadedModules.at(module_name);
	FreeLibrary(mod_data.hModule);

	m_loadedModules.erase(module_name);

	parse_process_modules();
}

Injector::ProcInfo Injector::parse_running_proccesses()
{
	auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		return {};
	}

	ProcInfo       proc_info;
	PROCESSENTRY32 proc_entry = { sizeof(PROCESSENTRY32) };
	if (!!Process32First(snap, &proc_entry)) {
		do {
			proc_info.insert(
#ifdef _UNICODE
				std::make_pair(unicode_to_string(proc_entry.szExeFile), proc_entry)
#else
				std::make_pair(proc_entry.szExeFile, proc_entry)
#endif
			);
		} while (!!Process32Next(snap, &proc_entry));
	}

	CloseHandle(snap);

	return std::move(proc_info);
}

Injector::ModuleInfo Injector::parse_loaded_modules(const uint32_t pid)
{
	if (!pid) {
		return {};
	}

	auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snap == INVALID_HANDLE_VALUE) {
		return {};
	}

	ModuleInfo module_info;
	MODULEENTRY32 module_entry = { sizeof(MODULEENTRY32) };
	if (!!Module32First(snap, &module_entry)) {
		do {
			module_info.insert(
#ifdef _UNICODE
				std::make_pair(unicode_to_string(module_entry.szModule), module_entry)
#else
				std::make_pair(module_entry.szModule, module_entry)
#endif
			);
		} while (!!Module32Next(snap, &module_entry));
	}

	CloseHandle(snap);

	return std::move(module_info);
}

/*
std::string Injector::get_directory_file_path(const std::string& file)
{
	char buffer[MAX_PATH + 1] = {};
	GetCurrentDirectoryA(MAX_PATH + 1, buffer);

	std::string directory(buffer);
	directory.append("");

	if (!file.empty()) {
		directory.append(file);
	}

	return directory;
}
*/