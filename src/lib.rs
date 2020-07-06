extern crate rusb;

use std::time::Duration;

type Handler = dyn FnMut(Vec<u8>);

fn send_at_message(device_handle: &rusb::DeviceHandle<rusb::GlobalContext>, line: String) {
    let device = device_handle.device();
    let config_desc = device.config_descriptor(0).unwrap();
    let interface = config_desc.interfaces().nth(1).unwrap();
    let interface_desc = interface.descriptors().nth(0).unwrap();
    let out_endpoint = interface_desc
        .endpoint_descriptors()
        .find(|endpoint| {
            return endpoint.direction() == rusb::Direction::Out
                && endpoint.transfer_type() == rusb::TransferType::Bulk;
        })
        .unwrap();
    let timeout = Duration::from_secs(0);
    device_handle
        .write_bulk(out_endpoint.address(), line.as_bytes(), timeout)
        .unwrap();
}

pub fn send_can_frame(
    device_handle: &rusb::DeviceHandle<rusb::GlobalContext>,
    arbitration_id: u32,
    frame: &[u8],
) {
    println!(
        "arbitration_id = {:08x} frame = {:?}",
        arbitration_id, frame
    );
    let device = device_handle.device();
    let config_desc = device.config_descriptor(0).unwrap();
    let interface = config_desc.interfaces().nth(1).unwrap();
    let interface_desc = interface.descriptors().nth(0).unwrap();
    let out_endpoint = interface_desc
        .endpoint_descriptors()
        .find(|endpoint| {
            return endpoint.direction() == rusb::Direction::Out
                && endpoint.transfer_type() == rusb::TransferType::Bulk;
        })
        .unwrap();
    let channel_id = 0x05;
    let data_size = 12; // 8 bytes CAN + 4 bytes arb ID
    let tx_flags = 0x00; // CAN_11BIT_ID
    let at_command = format!(
        "att{channel_id} {data_size} {tx_flags}\r\n",
        channel_id = channel_id,
        data_size = data_size,
        tx_flags = tx_flags
    );
    let mut buffer: Vec<u8> = vec![];
    buffer.extend_from_slice(&at_command.as_bytes());
    buffer.extend_from_slice(&arbitration_id.to_be_bytes());
    buffer.extend_from_slice(&frame);
    let timeout = Duration::from_secs(0);
    device_handle
        .write_bulk(out_endpoint.address(), &buffer, timeout)
        .unwrap();
}

fn process_buffer(buffer: &Vec<u8>, handler: &mut Handler) -> usize {
    let mut i = 0;
    let mut bytes_processed = 0;
    while i < buffer.len() {
        // short circuit, we need at least 4 bytes to get started
        if i + 4 > buffer.len() {
            break;
        }
        // check for ar5 packet (5 is CAN protocol ID)
        if buffer[i] == 0x61 && buffer[i + 1] == 0x72 && buffer[i + 2] == 0x35 {
            let payload_length = buffer[i + 3] as usize;
            if i + 4 + payload_length > buffer.len() {
                break;
            }
            let payload = &buffer[i + 4..i + 4 + payload_length];
            let _header = &payload[0..5];
            let body = &payload[5..];
            (*handler)(body.to_vec());
            i = i + 4 + payload_length;
            bytes_processed = i;
        } else {
            i = i + 1;
        }
    }
    return bytes_processed;
}

pub fn recv(device_handle: &rusb::DeviceHandle<rusb::GlobalContext>, handler: &mut Handler) {
    let device = device_handle.device();
    let config_desc = device.config_descriptor(0).unwrap();
    let interface = config_desc.interfaces().nth(1).unwrap();
    let interface_desc = interface.descriptors().nth(0).unwrap();
    let in_endpoint = interface_desc
        .endpoint_descriptors()
        .find(|endpoint| {
            return endpoint.direction() == rusb::Direction::In
                && endpoint.transfer_type() == rusb::TransferType::Bulk;
        })
        .unwrap();
    let mut buffer: Vec<u8> = vec![];
    loop {
        let max_packet_size = in_endpoint.max_packet_size() as usize;
        let mut vec = vec![0; max_packet_size];
        let timeout = Duration::from_secs(0);
        device_handle
            .read_bulk(in_endpoint.address(), &mut vec, timeout)
            .unwrap();
        buffer.extend(&vec);
        let bytes_processed = process_buffer(&buffer, handler);
        buffer = buffer[bytes_processed..].to_vec();
    }
}

fn pass_thru_open(device_handle: &rusb::DeviceHandle<rusb::GlobalContext>) {
    send_at_message(device_handle, format!("\r\n\r\nati\r\n"));
    send_at_message(device_handle, format!("ata\r\n"));
}

fn pass_thru_connect(device_handle: &rusb::DeviceHandle<rusb::GlobalContext>) {
    let protocol_id = 0x00000005; // CAN
    let flags = 0x0800; // CAN_ID_BOTH
    let baud = 500000;
    send_at_message(
        device_handle,
        format!(
            "ato{protocol_id} {flags} {baud} 0\r\n",
            protocol_id = protocol_id,
            flags = flags,
            baud = baud
        ),
    );
}

fn pass_thru_start_msg_filter(device_handle: &rusb::DeviceHandle<rusb::GlobalContext>) {
    let protocol_id = 0x00000005; // CAN
    let filter_type = 0x01; // PASS_FILTER
    let tx_flags = 0x00000040; // ISO15765_FRAME_PAD
    let mask_msg = String::from("\0\0\0\0");
    let pattern_msg = String::from("\0\0\0\0");
    send_at_message(
        device_handle,
        format!(
            "atf{protocol_id} {filter_type} {tx_flags} 4\r\n{mask_msg}{pattern_msg}",
            protocol_id = protocol_id,
            filter_type = filter_type,
            tx_flags = tx_flags,
            mask_msg = mask_msg,
            pattern_msg = pattern_msg
        ),
    );
}

fn get_device_handle() -> rusb::DeviceHandle<rusb::GlobalContext> {
    let vendor_id = 0x0403;
    let product_id = 0xcc4d;
    let device = rusb::devices()
        .unwrap()
        .iter()
        .find(|device| {
            let device_desc = device.device_descriptor().unwrap();
            return device_desc.vendor_id() == vendor_id && device_desc.product_id() == product_id;
        })
        .unwrap();
    let mut device_handle = device.open().unwrap();
    let config_desc = device.config_descriptor(0).unwrap();
    let interface = config_desc.interfaces().nth(1).unwrap();
    let interface_desc = interface.descriptors().nth(0).unwrap();
    device_handle
        .set_active_configuration(config_desc.number())
        .unwrap();
    device_handle
        .claim_interface(interface_desc.interface_number())
        .unwrap();
    device_handle
        .set_alternate_setting(
            interface_desc.interface_number(),
            interface_desc.setting_number(),
        )
        .unwrap();
    return device_handle;
}

pub fn new() -> rusb::DeviceHandle<rusb::GlobalContext> {
    let device_handle = get_device_handle();
    pass_thru_open(&device_handle);
    pass_thru_connect(&device_handle);
    pass_thru_start_msg_filter(&device_handle);
    return device_handle;
}
