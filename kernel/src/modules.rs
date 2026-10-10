//! Task images, loaded by Limine as boot modules (`module_path` + `module_string` in
//! limine.conf; the Makefile adds one per program). They sit in memory only the kernel can
//! reach, through the direct map, for the whole run, so a restart reloads the same bytes.

use spin::Once;

const MAX_MODULES: usize = 32;

/// (module string = program name, contents).
static MODULES: Once<[Option<(&'static [u8], &'static [u8])>; MAX_MODULES]> = Once::new();

pub fn init(files: &[&'static limine::file::File]) {
    MODULES.call_once(|| {
        let mut modules = [None; MAX_MODULES];
        for (slot, file) in modules.iter_mut().zip(files) {
            let name = file.string().to_bytes();
            let data = unsafe { core::slice::from_raw_parts(file.addr(), file.size() as usize) };
            *slot = Some((name, data));
        }
        assert!(files.len() <= MAX_MODULES, "more than {MAX_MODULES} boot modules");
        modules
    });
}

/// The image of program `name`, if Limine loaded it.
pub fn find(name: &str) -> Option<&'static [u8]> {
    MODULES.get()?.iter().flatten().find(|(n, _)| *n == name.as_bytes()).map(|(_, data)| *data)
}
