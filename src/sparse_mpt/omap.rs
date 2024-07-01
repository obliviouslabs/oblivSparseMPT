#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// Create a wrapper around the generated bindings for omap to make it more idiomatic
// use macro to access the bindings for different key and value sizes

use std::ffi::c_void;

fn getConstCVoidPtr<T>(valptr: &T) -> *const c_void {
    let ptr = valptr as *const _ as *const c_void;
    ptr
}

fn getMutCVoidPtr<T>(valptr: &mut T) -> *mut c_void {
    let ptr = valptr as *mut _ as *mut c_void;
    ptr
}

#[derive(Debug)]
pub enum OMapBinding {
    OMapBinding_8_8(OMapBinding_8_8),
    OMapBinding_20_32(OMapBinding_20_32),
    OMapBinding_32_532(OMapBinding_32_532),
}

use ahash::{HashMap, HashMapExt, RandomState};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug)]
pub struct OMap<K, V> {
    inner: OMapBinding,
    _marker: PhantomData<(K, V)>,
}

#[derive(Debug)]
pub struct ChangeLogEntry<K, V> {
    key: K,
    value: V,
    isInsert: bool,
}

#[derive(Debug, Clone)]
pub struct ScalableOMap<K, V> {
    omap: Arc<Mutex<OMap<K, V>>>,                      // the underlying omap
    hashmap: Arc<Mutex<HashMap<K, V>>>,                // the reference hashmap for upscaling
    change_log: Arc<Mutex<Vec<ChangeLogEntry<K, V>>>>, // log the changes during upscaling
    current_capacity: u32,                             // the current capacity of the omap
    resizing_flag: Arc<AtomicBool>,                    // mutex for resizing
    block_modify_flag: Arc<AtomicBool>, // if this flag is true, block all modifications
    cache_in_byte: u64,
}

// Define a macro to implement OMap for different key-value combinations
macro_rules! impl_omap {
    ($k:ty, $v:ty, $variant:ident) => {
        impl OMap<$k, $v> {
            pub fn new() -> Self {
                Self {
                    inner: unsafe { OMapBinding::$variant($variant::new()) },
                    _marker: PhantomData,
                }
            }

            pub fn init_empty(&mut self, sz: u32) {
                if let OMapBinding::$variant(omap) = &mut self.inner {
                    unsafe {
                        (*omap).InitEmpty(sz);
                    }
                }
            }

            pub fn init_empty_external(&mut self, sz: u32, cache_in_byte: u64) {
                if let OMapBinding::$variant(omap) = &mut self.inner {
                    unsafe {
                        (*omap).InitEmptyExternal(sz, cache_in_byte);
                    }
                }
            }

            pub fn insert(&mut self, key: &$k, val: &$v, isOblivious: bool) {
                if let OMapBinding::$variant(omap) = &mut self.inner {
                    unsafe {
                        if isOblivious {
                            (*omap).OInsert(getConstCVoidPtr(key), getConstCVoidPtr(val));
                        } else {
                            (*omap).Insert(getConstCVoidPtr(key), getConstCVoidPtr(val));
                        }
                    }
                }
            }

            pub fn get(&mut self, key: &$k) -> Option<$v> {
                // let mut rv: $v = 0;
                let mut rv: $v = unsafe { std::mem::zeroed() };
                if let OMapBinding::$variant(omap) = &mut self.inner {
                    let flag =
                        unsafe { (*omap).Find(getConstCVoidPtr(key), getMutCVoidPtr(&mut rv)) };
                    if flag {
                        Some(rv)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }

            pub fn erase(&mut self, key: &$k, isOblivious: bool) {
                if let OMapBinding::$variant(omap) = &mut self.inner {
                    unsafe {
                        if isOblivious {
                            (*omap).OErase(getConstCVoidPtr(key));
                        } else {
                            (*omap).Erase(getConstCVoidPtr(key));
                        }
                    }
                }
            }

            pub fn start_init(&mut self, sz: u32) {
                if let OMapBinding::$variant(omap) = &mut self.inner {
                    unsafe {
                        (*omap).StartInit(sz);
                    }
                }
            }

            pub fn finish_init(&mut self) {
                if let OMapBinding::$variant(omap) = &mut self.inner {
                    unsafe {
                        (*omap).FinishInit();
                    }
                }
            }

            pub fn start_init_external(&mut self, sz: u32, cache_in_byte: u64) {
                if let OMapBinding::$variant(omap) = &mut self.inner {
                    unsafe {
                        (*omap).StartInitExternal(sz, cache_in_byte);
                    }
                }
            }
        }
    };
}

macro_rules! drop_omap_impl {
    ($($variant:ident),*) => {
        impl<K, V> Drop for OMap<K, V> {
            fn drop(&mut self) {
                match &mut self.inner {
                    $(
                        OMapBinding::$variant(omap) => unsafe {
                            omap.Destroy();
                        },
                    )*
                }
            }
        }
    };
}

macro_rules! impl_scalable_omap {
    ($k:ty, $v:ty) => {
        impl ScalableOMap<$k, $v> {
            pub fn new() -> Self {
                Self {
                    omap: Arc::new(Mutex::new(OMap::<$k, $v>::new())),
                    hashmap: Arc::new(Mutex::new(HashMap::<$k, $v>::new())),
                    change_log: Arc::new(Mutex::new(Vec::new())),
                    current_capacity: 0,
                    resizing_flag: Arc::new(AtomicBool::new(false)),
                    block_modify_flag: Arc::new(AtomicBool::new(false)),
                    cache_in_byte: 0,
                }
            }

            // clone method for ScalableOMap, shallow copy the Arcs
            pub fn clone(&self) -> Self {
                Self {
                    omap: self.omap.clone(),
                    hashmap: self.hashmap.clone(),
                    change_log: self.change_log.clone(),
                    current_capacity: self.current_capacity,
                    resizing_flag: self.resizing_flag.clone(),
                    block_modify_flag: self.block_modify_flag.clone(),
                    cache_in_byte: self.cache_in_byte,
                }
            }

            pub fn init_empty(&mut self, sz: u32) {
                self.omap.lock().unwrap().init_empty(sz);
                self.current_capacity = sz;
            }

            pub fn init_empty_external(&mut self, sz: u32, cache_in_byte: u64) {
                self.omap
                    .lock()
                    .unwrap()
                    .init_empty_external(sz, cache_in_byte);
                self.current_capacity = sz;
                self.cache_in_byte = cache_in_byte;
            }

            fn resize(&mut self) {
                // create a new omap with double the capacity
                let new_omap = Arc::new(Mutex::new(OMap::<$k, $v>::new()));
                let mut new_omap_locked = new_omap.lock().unwrap();
                if self.cache_in_byte != 0 {
                    new_omap_locked.start_init_external(self.current_capacity, self.cache_in_byte);
                } else {
                    new_omap_locked.start_init(self.current_capacity);
                }
                // copy the current hashmap to the new omap
                let mut hashmap_locked = self.hashmap.lock().unwrap();
                for (k, v) in hashmap_locked.iter() {
                    new_omap_locked.insert(k, v, false);
                }
                // finish the initialization
                new_omap_locked.finish_init();
                // set the block modify flag to true to block all future insertions/erasures
                // until the resizing finishes
                self.block_modify_flag.store(true, Ordering::Relaxed);

                let mut log = self.change_log.lock().unwrap();

                // copy the change log to the new omap and the hashmap
                for log_entry in log.iter() {
                    let is_insert = log_entry.isInsert;
                    if is_insert {
                        new_omap_locked.insert(&log_entry.key, &log_entry.value, false);
                        hashmap_locked.insert(log_entry.key, log_entry.value);
                    } else {
                        new_omap_locked.erase(&log_entry.key, false);
                        hashmap_locked.remove(&log_entry.key);
                    }
                }
                {
                    let mut omap_locked = self.omap.lock().unwrap();
                    std::mem::swap(&mut *omap_locked, &mut *new_omap_locked);
                }
                log.clear();
                println!(
                    "Resizing finished, current capacity: {}",
                    self.current_capacity
                );
                self.resizing_flag.store(false, Ordering::Relaxed);
                self.block_modify_flag.store(false, Ordering::Relaxed);
            }

            pub fn insert(&mut self, key: &$k, val: &$v) {
                // since the insert takes a mutable reference to self, at most one insert can happen at a time
                // busy wait if the block modify flag is set, either because the resizer is
                // reading the log, or the log is too long and we have to pause the insertions
                while self.block_modify_flag.load(Ordering::Relaxed) {
                    // busy wait
                }

                if self.resizing_flag.load(Ordering::Relaxed) {
                    let mut log = self.change_log.lock().unwrap();
                    // the resizer might lock the change log before the last insert completes,
                    // at this point it has already read the log and set the resizing flag to false
                    // in that case, we should just insert as normal
                    if self.resizing_flag.load(Ordering::Relaxed) {
                        log.push(ChangeLogEntry {
                            key: *key,
                            value: *val,
                            isInsert: true,
                        });
                        {
                            self.omap.lock().unwrap().insert(key, val, false);
                        }
                        // if the log is too large, block future insertions/erasures
                        if log.len() >= (self.current_capacity / 5) as usize {
                            self.block_modify_flag.store(true, Ordering::Relaxed);
                        }
                        return;
                    }
                }
                let should_resize: bool;
                {
                    let mut hashmap_locked = self.hashmap.lock().unwrap();
                    hashmap_locked.insert(*key, *val);
                    {
                        self.omap.lock().unwrap().insert(key, val, false);
                    }
                    should_resize =
                        hashmap_locked.len() >= (self.current_capacity as f64 * 0.8) as usize;
                }
                if should_resize {
                    self.current_capacity *= 2;
                    // all subsequent changes will go to the log until the resizing finishes
                    self.resizing_flag.store(true, Ordering::Relaxed);
                    let mut self_clone = self.clone();
                    // start the resizing process with a background thread
                    let _handle = thread::spawn(move || {
                        self_clone.resize();
                    });
                }
            }

            pub fn get(&self, key: &$k) -> Option<$v> {
                // only read from the omap
                self.omap.lock().unwrap().get(key)
            }

            pub fn erase(&mut self, key: &$k) {
                // cannot modify the log while the resizer is reading it
                while self.block_modify_flag.load(Ordering::Relaxed) {
                    // busy wait
                }
                if self.resizing_flag.load(Ordering::Relaxed) {
                    let mut log = self.change_log.lock().unwrap();
                    if self.resizing_flag.load(Ordering::Relaxed) {
                        log.push(ChangeLogEntry {
                            key: *key,
                            value: unsafe { std::mem::zeroed() },
                            isInsert: false,
                        });
                        self.omap.lock().unwrap().erase(key, false);
                        return;
                    }
                }
                let mut hashmap_locked = self.hashmap.lock().unwrap();
                hashmap_locked.remove(key);
                self.omap.lock().unwrap().erase(key, false);
            }

            pub fn start_init(&mut self, sz: u32) {
                self.current_capacity = sz;
                self.omap.lock().unwrap().start_init(sz);
            }

            pub fn finish_init(&mut self) {
                self.omap.lock().unwrap().finish_init();
            }

            pub fn start_init_external(&mut self, sz: u32, cache_in_byte: u64) {
                self.current_capacity = sz;
                self.cache_in_byte = cache_in_byte;
                self.omap
                    .lock()
                    .unwrap()
                    .start_init_external(sz, cache_in_byte);
            }
        }
    };
}

impl_omap!(u64, u64, OMapBinding_8_8);
impl_omap!([u8; 20], [u8; 32], OMapBinding_20_32);
impl_omap!([u8; 32], [u8; 532], OMapBinding_32_532);
impl_scalable_omap!(u64, u64);
impl_scalable_omap!([u8; 32], [u8; 532]);

drop_omap_impl!(OMapBinding_8_8, OMapBinding_20_32, OMapBinding_32_532);

#[cfg(test)]
mod tests {

    use criterion::Bencher;

    use super::*;

    // rewrite the test to use the OMap struct

    #[test]
    fn test_omap_insert_and_get() {
        let sz = 100u32;
        let mut omap: OMap<u64, u64> = OMap::<u64, u64>::new();
        omap.init_empty(sz);
        omap.insert(&123u64, &456u64, false);
        omap.insert(&789u64, &101112u64, true);
        let rv1 = omap.get(&123u64);
        let rv2 = omap.get(&789u64);
        assert_eq!(rv1, Some(456u64));
        assert_eq!(rv2, Some(101112u64));
    }

    #[test]
    fn test_omap_larger_kv() {
        let sz = 100u32;
        let mut omap: OMap<[u8; 20], [u8; 32]> = OMap::<[u8; 20], [u8; 32]>::new();
        omap.init_empty(sz);
        let key1 = [1u8; 20];
        let key2 = [2u8; 20];
        let v1 = [3u8; 32];
        let v2 = [4u8; 32];
        omap.insert(&key1, &v1, false);
        omap.insert(&key2, &v2, true);
        let rv1 = omap.get(&key1);
        let rv2 = omap.get(&key2);

        assert_eq!(rv1, Some(v1));
        assert_eq!(rv2, Some(v2));
    }

    #[test]
    fn test_omap_init() {
        let sz = 1000u32;
        let mut omap: OMap<u64, u64> = OMap::<u64, u64>::new();
        omap.start_init(sz);
        omap.insert(&123u64, &456u64, false);
        omap.insert(&789u64, &101112u64, true);
        omap.finish_init();
        omap.insert(&432u64, &10u64, false);
        let rv1 = omap.get(&123u64);
        let rv2 = omap.get(&789u64);
        let rv3 = omap.get(&432u64);
        let rv4 = omap.get(&999u64);
        assert_eq!(rv1, Some(456u64));
        assert_eq!(rv2, Some(101112u64));
        assert_eq!(rv3, Some(10u64));
        assert_eq!(rv4, None);
    }

    #[test]
    fn test_omap_init_ext_mem() {
        let sz = 100000u32;
        let mut omap: OMap<u64, u64> = OMap::<u64, u64>::new();
        omap.start_init_external(sz, 2000000u64);
        omap.insert(&123u64, &456u64, false);
        omap.insert(&789u64, &101112u64, true);
        omap.finish_init();
        omap.insert(&432u64, &10u64, false);
        let rv1 = omap.get(&123u64);
        let rv2 = omap.get(&789u64);
        let rv3 = omap.get(&432u64);
        let rv4 = omap.get(&999u64);
        assert_eq!(rv1, Some(456u64));
        assert_eq!(rv2, Some(101112u64));
        assert_eq!(rv3, Some(10u64));
        assert_eq!(rv4, None);
    }

    #[test]
    fn test_omap_erase() {
        let sz = 1000u32;
        let mut omap: OMap<u64, u64> = OMap::<u64, u64>::new();
        omap.init_empty(sz);

        // insert two key-value pairs
        omap.insert(&123u64, &456u64, false);
        omap.insert(&789u64, &101112u64, true);

        // erase the first key-value pair
        omap.erase(&123u64, false);

        // check if the first key-value pair is erased
        let rv1 = omap.get(&123u64);
        assert_eq!(rv1, None);

        // check if the second key-value pair is still there
        let rv2 = omap.get(&789u64);
        assert_eq!(rv2, Some(101112u64));
    }

    #[test]
    fn test_omap_seq() {
        let sz = 100000u32;
        let mut omap: OMap<u64, u64> = OMap::<u64, u64>::new();
        omap.init_empty(sz);
        let mut keys = vec![0u64; 1000];
        let mut values = vec![0u64; 1000];
        for i in 0..1000 {
            keys[i] = i as u64;
            values[i] = i as u64 * 2;
            omap.insert(&keys[i], &values[i], false);
        }
        for i in 0..1000 {
            let rv = omap.get(&keys[i]);
            assert_eq!(rv, Some(values[i]));
        }
    }

    #[test]
    fn test_omap_random() {
        let sz = 100000u32;
        let mut omap: OMap<u64, u64> = OMap::<u64, u64>::new();
        let mut refmap: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
        omap.init_empty(sz);
        for _ in 0..sz {
            if rand::random::<bool>() {
                let key = rand::random::<u64>() % (sz * 3) as u64;
                let value = rand::random::<u64>();
                omap.insert(&key, &value, false);
                refmap.insert(key, value);
            } else if rand::random::<bool>() && !refmap.is_empty() {
                let key = *refmap
                    .keys()
                    .nth(rand::random::<usize>() % refmap.len())
                    .unwrap();
                omap.erase(&key, false);
                refmap.remove(&key);
            }
            let searchkey = rand::random::<u64>() % (sz * 3) as u64;
            let rv = omap.get(&searchkey);
            let refrv = refmap.get(&searchkey);
            if let Some(v) = refrv {
                assert_eq!(rv, Some(*v));
            } else {
                assert_eq!(rv, None);
            }
        }
    }

    #[test]
    fn test_scalable_omap_random() {
        let sz = 100u32;
        let mut omap: ScalableOMap<u64, u64> = ScalableOMap::<u64, u64>::new();
        let mut refmap: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
        omap.init_empty(sz);
        for i in 0..sz * 1000 {
            if rand::random::<bool>() {
                let key = rand::random::<u64>() % (i * 5 + 1) as u64;
                let value = rand::random::<u64>();
                omap.insert(&key, &value);
                refmap.insert(key, value);
            } else if rand::random::<bool>() && !refmap.is_empty() {
                let key = rand::random::<u64>() % (i * 5 + 1) as u64;
                omap.erase(&key);
                refmap.remove(&key);
            }
            let searchkey = rand::random::<u64>() % (i * 5 + 1) as u64;
            let rv = omap.get(&searchkey);
            let refrv = refmap.get(&searchkey);
            if let Some(v) = refrv {
                assert_eq!(rv, Some(*v));
            } else {
                assert_eq!(rv, None);
            }
        }
        // check the maps agree
        for (k, v) in refmap.iter() {
            let rv = omap.get(k);
            assert_eq!(rv, Some(*v));
        }
    }

    #[test]
    #[ignore]
    fn test_scalable_omap_perf() {
        let min_sz = 100000u32;
        let max_sz = 1000000u32;
        // 32-byte key and 532-byte value
        unsafe {
            ResetBackend((max_sz as u64) * 4096);
        }
        let mut omap: ScalableOMap<[u8; 32], [u8; 532]> =
            ScalableOMap::<[u8; 32], [u8; 532]>::new();
        let insertStart = std::time::Instant::now();
        omap.init_empty_external(min_sz, 200000000u64);
        for i in min_sz..max_sz {
            let mut key = [0 as u8; 32];
            let value = [0 as u8; 532];
            // mem copy the index to the key
            key[0..4].copy_from_slice(&i.to_be_bytes());

            omap.insert(&key, &value);
        }
        let insertDuration = insertStart.elapsed();
        println!("Insertion time: {:?}", insertDuration / (max_sz - min_sz));
        // start timing
        let round = 100000;
        let findStart = std::time::Instant::now();
        for i in 0..round {
            let mut searchkey = [0 as u8; 32];
            searchkey[0..4].copy_from_slice(&(i + min_sz - 1000).to_be_bytes());
            omap.get(&searchkey);
        }
        let findDuration = findStart.elapsed();
        println!("Find time: {:?}", findDuration / round);
    }
}
