#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <unordered_map>

#include <codecvt>
#include <fstream>
#include <iostream>
#include <algorithm>

class Injector
{
	/// <summary>
	/// Information describing the proc.
	/// </summary>
	using ProcInfo = std::unordered_map<std::string, PROCESSENTRY32>;

	/// <summary>
	/// Information describing the module.
	/// </summary>
	using ModuleInfo = std::unordered_map<std::string, MODULEENTRY32>;

public:

	uint32_t get_pid(const std::string& processname);
	bool inject(const std::string& filename);
	bool inject(const uint32_t pid, const std::string& filename);

	//determines if we can parse process modules.
	bool parse_process_modules();

	//search for first target process with process_name
	bool find_target_process(const std::string& process_name);

	inline const ModuleInfo& get_loaded_modules() const;

	ModuleInfo parse_loaded_modules() const;

	//ejects module_name
	void eject(const std::string& module_name);

	static ProcInfo parse_running_proccesses();

	static ModuleInfo parse_loaded_modules(const uint32_t pid);

	//gets directory for the path of file
	//static std::string get_directory_file_path(const std::string& file);

private:
	//process id
	uint32_t   m_processId = 0;

	//function of LoadLibrarA.
	uintptr_t  m_loadLibrary = 0;
	
	//loaded modules
	ModuleInfo m_loadedModules;
};

inline const Injector::ModuleInfo& Injector::get_loaded_modules() const
{
	return m_loadedModules;
}