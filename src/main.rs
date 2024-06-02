extern crate winapi;
use std::env;
use std::ffi::CStr;
use std::ffi::CString;
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::handleapi::CloseHandle;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use std::ptr::null_mut;
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::memoryapi::VirtualAllocEx;
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::winnt::{MEM_COMMIT, PAGE_READWRITE, PROCESS_ALL_ACCESS};


// mod injection;
// mod processes;

// Constants
const PROCESS_NAME: &str = r"Client-Win64-Shipping.exe";
const DLL_NAME: &str = "Wu.dll";

fn main() {
    let binding = env::current_dir().expect("Failed to get current directory").join(DLL_NAME);
    let dll_path = binding.to_str().expect("failed");

    // println!("{}", &dll_path);

    if let Some(target_process) = find_process_id_by_name(PROCESS_NAME) {
        match inject_dll(target_process, &dll_path) {
            Ok(_) => println!("injected in {}", target_process),
            Err(e) => println!("failed injection in {}, error {}", target_process, e)
        }
    } else {
        println!("failed to find process {}", PROCESS_NAME);
    }
}


fn process_snapshot() -> Result<*mut winapi::ctypes::c_void, &'static str> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        Err("Failed to create snapshot of current processes.")
    } else {
        Ok(snapshot)
    }
}

fn first_process_entry(
    snapshot: *mut winapi::ctypes::c_void,
) -> Result<PROCESSENTRY32, &'static str> {
    let mut pe32: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    pe32.dwSize = std::mem::size_of::<PROCESSENTRY32>() as DWORD;
    let success = unsafe { Process32First(snapshot, &mut pe32) };

    if success == FALSE {
        unsafe { CloseHandle(snapshot) };
        Err("Failed to gather information about the first process.")
    } else {
        Ok(pe32)
    }
}

fn iterate_processes<F: FnMut(PROCESSENTRY32) -> bool>(
    mut callback: F,
) -> Result<(), &'static str> {
    let snapshot = process_snapshot()?;
    let mut pe32 = first_process_entry(snapshot)?;

    loop {
        if !callback(pe32) || unsafe { Process32Next(snapshot, &mut pe32) } == FALSE {
            break;
        }
    }

    unsafe { CloseHandle(snapshot) };
    Ok(())
}

fn find_process_id_by_name(name: &str) -> Option<DWORD> {
    let name = name.to_lowercase();
    let mut pid = None;

    let _ = iterate_processes(|pe32| {
        let process_name = unsafe {
            CStr::from_ptr(pe32.szExeFile.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        let is_target_process_found = process_name.to_lowercase() == name;

        if is_target_process_found {
            println!(
                "Found process: {}, Process ID: {}",
                process_name, pe32.th32ProcessID
            );
            pid = Some(pe32.th32ProcessID);
        }

        !is_target_process_found
    });

    if pid.is_none() {
        eprintln!("No process found with name: {}", name);
    }

    pid
}

fn inject_dll(pid: DWORD, dll_path: &str) -> Result<(), String> {
    let dll_path_cstring = CString::new(dll_path.to_string()).expect("CString::new failed");

    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if process.is_null() {
            return Err("Failed to open the target process.".to_string());
        }

        let addr = VirtualAllocEx(
            process,
            null_mut(),
            dll_path_cstring.to_bytes_with_nul().len(),
            MEM_COMMIT,
            PAGE_READWRITE,
        );
        if addr.is_null() {
            return Err("Failed to allocate memory in the target process.".to_string());
        }

        if winapi::um::memoryapi::WriteProcessMemory(
            process,
            addr,
            dll_path_cstring.as_ptr() as *const _,
            dll_path_cstring.to_bytes_with_nul().len(),
            null_mut(),
        ) == 0
        {
            return Err("Failed to write into the target process memory.".to_string());
        }

        let kernel32 = CString::new("kernel32.dll").expect("CString::new failed");
        let loadlibrarya = CString::new("LoadLibraryA").expect("CString::new failed");

        let h_kernel32 = GetModuleHandleA(kernel32.as_ptr());
        if h_kernel32.is_null() {
            return Err("Failed to get the handle of kernel32.dll.".to_string());
        }

        let h_loadlibrarya =
            winapi::um::libloaderapi::GetProcAddress(h_kernel32, loadlibrarya.as_ptr());
        if h_loadlibrarya.is_null() {
            return Err("Failed to get the address of LoadLibraryA.".to_string());
        }

        if CreateRemoteThread(
            process,
            null_mut(),
            0,
            Some(std::mem::transmute(h_loadlibrarya)),
            addr as *mut _,
            0,
            null_mut(),
        )
        .is_null()
        {
            return Err("Failed to create a remote thread in the target process.".to_string());
        }

        CloseHandle(process);
    }

    Ok(())
}