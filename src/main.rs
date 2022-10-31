#![no_main]
#![no_std]
#![feature(abi_efiapi)]

use log::{debug, info};

extern crate alloc;

use alloc::vec::Vec;

use uefi::prelude::*;
use uefi::proto::device_path::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::network::pxe::BaseCode;
use uefi::proto::network::pxe::DhcpV4Packet;
use uefi::proto::network::IpAddress;
use uefi::table::boot::*;
use uefi::CStr8;

/// Memory Mapped Device Path.
#[repr(C, packed)]
pub struct MemoryMappedDevicePath {
    header: DevicePathHeader,
    memory_type: u32,
    starting_address: u64,
    ending_address: u64,
}

/// Create Memory Mapped Device Path
fn create_memory_mapped_device_path(start: u64, end: u64) -> Vec<u8> {
    let mut raw_data: Vec<u8> = Vec::new();
    let mmdp: MemoryMappedDevicePath = MemoryMappedDevicePath {
        header: (DevicePathHeader {
            device_type: (DeviceType::HARDWARE),
            sub_type: (DeviceSubType::HARDWARE_MEMORY_MAPPED),
            length: (core::mem::size_of::<MemoryMappedDevicePath>()
                .try_into()
                .unwrap()),
        }),
        memory_type: (MemoryType::BOOT_SERVICES_CODE.0),
        starting_address: (start),
        ending_address: (end),
    };

    raw_data.extend_from_slice(unsafe {
        core::slice::from_raw_parts(
            (&mmdp as *const MemoryMappedDevicePath) as *const u8,
            core::mem::size_of::<MemoryMappedDevicePath>(),
        )
    });

    let dp_end: DevicePathHeader = DevicePathHeader {
        device_type: (DeviceType::END),
        sub_type: (DeviceSubType::END_ENTIRE),
        length: (core::mem::size_of::<DevicePathHeader>().try_into().unwrap()),
    };

    raw_data.extend_from_slice(unsafe {
        core::slice::from_raw_parts(
            (&dp_end as *const DevicePathHeader) as *const u8,
            core::mem::size_of::<DevicePathHeader>(),
        )
    });

    raw_data
}

const RUSTV_FILE: &[u8] = b"rust_v.efi\0";

#[entry]
fn main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut system_table).unwrap();
    info!("Loader started ...");
    let bt = system_table.boot_services();
    let loaded_image = bt
        .open_protocol_exclusive::<LoadedImage>(image_handle)
        .unwrap();
    let mut base_code = bt
        .open_protocol_exclusive::<BaseCode>(loaded_image.device())
        .unwrap();
    assert!(base_code.mode().dhcp_ack_received);
    let dhcp_ack: &DhcpV4Packet = base_code.mode().dhcp_ack.as_ref();
    let server_ip = dhcp_ack.bootp_si_addr;
    info!("Server IPv4: {:?}", server_ip);
    let server_ip = IpAddress::new_v4(server_ip);

    let file_name = CStr8::from_bytes_with_nul(RUSTV_FILE).unwrap();
    debug!("Getting remote file size");
    let file_size = base_code
        .tftp_get_file_size(&server_ip, file_name)
        .expect("failed to query file size");
    debug!("file size {}", file_size);

    let buf = bt.allocate_pool(
        MemoryType::BOOT_SERVICES_CODE,
        file_size.try_into().unwrap(),
    );
    let ptr: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(buf.unwrap(), file_size.try_into().unwrap()) };
    let len = base_code
        .tftp_read_file(&server_ip, file_name, Some(ptr))
        .expect("failed to download file");
    base_code.stop().unwrap();
    debug!("PXE done ...");
    assert_eq!(file_size, len);

    let raw_data =
        create_memory_mapped_device_path(ptr.as_ptr() as u64, (ptr.as_ptr() as u64) + len);
    let dp = unsafe { DevicePath::from_ffi_ptr(raw_data.as_ptr().cast()) };
    debug!("Loading driver ...");

    let handle = bt
        .load_image(
            image_handle,
            LoadImageSource::FromBuffer {
                buffer: (ptr),
                file_path: (Some(&dp)),
            },
        )
        .expect("load failed");

    debug!("Loading done");

    info!("Starting image ...");
    bt.start_image(handle).expect("failed to start image");
    info!("Start Image done");
    bt.stall(100_000_000);
    Status::SUCCESS
}
