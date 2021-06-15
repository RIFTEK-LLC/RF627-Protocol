#include "RF627protocol.h"
#include "netwok_platform.h"
#include "memory_platform.h"
#include "custom_vector.h"
#include "endian_conv.h"

#include <string.h>

//
// rf627_protocol_get_size
//
rfUint32 rf627_protocol_old_get_size_of_header()
{
    return RF627_PROTOCOL_OLD_HEADER_SIZE;
}
rfUint32 rf627_protocol_old_get_size_of_request_hello_packet()
{
    return rf627_protocol_old_get_size_of_header();
}
rfUint32 rf627_protocol_old_get_size_of_response_hello_packet()
{
    return rf627_protocol_old_get_size_of_header() +
            RF627_PROTOCOL_OLD_HELLO_RESPONSE_PACKET_SIZE;
}
rfUint32 rf627_protocol_old_get_size_of_request_read_user_params_packet()
{
    return rf627_protocol_old_get_size_of_header();
}

rfUint32 rf627_protocol_old_get_size_of_response_profile_header_packet()
{
    return RF627_PROTOCOL_OLD_PROFILE_RESPONSE_HEADER_SIZE;
}
rfUint32 rf627_protocol_old_get_size_of_response_read_user_params_packet()
{
    return rf627_protocol_old_get_size_of_header() +
            RF627_PROTOCOL_OLD_USER_RESPONSE_PACKET_SIZE;
}
rfUint32 rf627_protocol_old_get_size_of_response_read_factory_params_packet()
{
    return rf627_protocol_old_get_size_of_header() +
            RF627_PROTOCOL_OLD_FACTORY_RESPONSE_PACKET_SIZE;
}
rfUint32 rf627_protocol_old_get_size_of_request_write_user_params_payload_packet()
{
    return RF627_PROTOCOL_OLD_USER_REQUEST_PAYLOAD_PACKET_SIZE;
}
rfUint32 rf627_protocol_old_get_size_of_request_write_user_sensor_params_payload_packet()
{
    return RF627_PROTOCOL_OLD_USER_SENSOR_REQUEST_PAYLOAD_PACKET_SIZE;
}

rfUint32 rf627_protocol_old_get_size_of_response_write_user_params_packet()
{
    return rf627_protocol_old_get_size_of_header();
}

rfUint32 rf627_protocol_old_get_size_of_response_save_user_params_packet()
{
    return rf627_protocol_old_get_size_of_header();
}





//
// rf627_protocol_create
//
rf627_old_header_msg_t rf627_protocol_old_create_header_msg(
        rfUint8                                  reserved_1,
        rf627_protocol_old_header_checksum_t     checksum,
        rf627_protocol_old_header_last_command_t is_last,
        rf627_protocol_old_header_confirmation_t confirmation,
        rf627_protocol_old_header_msg_type_t     msg_type,
        rfUint8                                  msg_options,
        rfUint8                                  data_checksum,
        rfUint8                                  reserved_2,
        rfUint32                                 serial_number,
        rfUint16                                 msg_count,
        rf627_protocol_old_header_cmd_t          cmd,
        rfUint16                                 payload_size
        )
{
    rf627_old_header_msg_t msg = {0};

    msg.reserved_1 = reserved_1;
    msg.checksum = checksum;
    msg.is_last = is_last;
    msg.confirmation = confirmation;
    msg.msg_type = msg_type;
    msg.msg_options = msg_options;
    msg.data_checksum = data_checksum;
    msg.reserved_2 = reserved_2;
    msg.serial_number = serial_number;
    msg.msg_count = msg_count;
    msg.cmd = cmd;
    msg.payload_size = payload_size;

    return msg;
}

rf627_old_header_msg_t rf627_protocol_old_create_hello_msg_request()
{
    rf627_old_header_msg_t msg = rf627_protocol_old_create_header_msg(
                0,
                kRF627_OLD_PROTOCOL_HEADER_CHECKSUM_OFF,
                kRF627_OLD_PROTOCOL_HEADER_LAST_COMMAND,
                kRF627_OLD_PROTOCOL_HEADER_CONFIRMATION_OFF,
                kRF627_OLD_PROTOCOL_HEADER_COMMAND_MSG,
                0,
                0,
                0,
                DEVICE_ID_ALL,
                0,
                kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_DEVICE_INFO,
                0
                );
    return msg;
}

rf627_old_header_msg_t rf627_protocol_old_create_read_user_params_msg_request(
        rf627_protocol_old_header_confirmation_t confirmation,
        rfUint32 serial_number,
        rfUint16 msg_count)
{
    rf627_old_header_msg_t msg = rf627_protocol_old_create_header_msg(
                0,
                kRF627_OLD_PROTOCOL_HEADER_CHECKSUM_OFF,
                kRF627_OLD_PROTOCOL_HEADER_LAST_COMMAND,
                confirmation,
                kRF627_OLD_PROTOCOL_HEADER_COMMAND_MSG,
                0,
                0,
                0,
                serial_number,
                msg_count,
                kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_PARAMS,
                0
                );
    return msg;
}

rf627_old_header_msg_t rf627_protocol_old_create_read_factory_params_msg_request(
        rf627_protocol_old_header_confirmation_t confirmation,
        rfUint32 serial_number,
        rfUint16 msg_count)
{
    rf627_old_header_msg_t msg = rf627_protocol_old_create_header_msg(
                0,
                kRF627_OLD_PROTOCOL_HEADER_CHECKSUM_OFF,
                kRF627_OLD_PROTOCOL_HEADER_LAST_COMMAND,
                confirmation,
                kRF627_OLD_PROTOCOL_HEADER_COMMAND_MSG,
                0,
                0,
                0,
                serial_number,
                msg_count,
                kRF627_OLD_PROTOCOL_HEADER_CMD_GET_FACTORY_PARAMS,
                0
                );
    return msg;
}

rf627_old_header_msg_t rf627_protocol_old_create_write_user_params_msg_request(
        rf627_protocol_old_header_confirmation_t confirmation,
        rfUint32 serial_number,
        rfUint16 msg_count)
{
    rf627_old_header_msg_t msg = rf627_protocol_old_create_header_msg(
                0,
                kRF627_OLD_PROTOCOL_HEADER_CHECKSUM_OFF,
                kRF627_OLD_PROTOCOL_HEADER_LAST_COMMAND,
                confirmation,
                kRF627_OLD_PROTOCOL_HEADER_COMMAND_MSG,
                0,
                0,
                0,
                serial_number,
                msg_count,
                kRF627_OLD_PROTOCOL_HEADER_CMD_SET_USER_PARAMS,
                rf627_protocol_old_get_size_of_request_write_user_params_payload_packet()
                );
    return msg;
}

rf627_old_header_msg_t rf627_protocol_old_create_write_user_sensor_params_msg_request(
        rf627_protocol_old_header_confirmation_t confirmation,
        rfUint32 serial_number,
        rfUint16 msg_count)
{
    rf627_old_header_msg_t msg = rf627_protocol_old_create_header_msg(
                0,
                kRF627_OLD_PROTOCOL_HEADER_CHECKSUM_OFF,
                kRF627_OLD_PROTOCOL_HEADER_LAST_COMMAND,
                confirmation,
                kRF627_OLD_PROTOCOL_HEADER_COMMAND_MSG,
                0,
                0,
                0,
                serial_number,
                msg_count,
                kRF627_OLD_PROTOCOL_HEADER_CMD_SET_USER_SENSOR,
                rf627_protocol_old_get_size_of_request_write_user_sensor_params_payload_packet()
                );
    return msg;
}

rfSize rf627_protocol_old_create_confirm_packet_from_response_packet(
        rfUint8* destination_buffer, rfUint32 destination_buffer_size,
        rfUint8* source_buffer, rfUint32 source_buffer_size)
{
    if (destination_buffer_size >= rf627_protocol_old_get_size_of_header() &&
            source_buffer_size >= rf627_protocol_old_get_size_of_header())
    {
        rf627_old_header_msg_t recv_msg =
                rf627_protocol_old_unpack_header_msg_from_packet(source_buffer);

        if (recv_msg.confirmation == kRF627_OLD_PROTOCOL_HEADER_CONFIRMATION_ON)
        {
            rf627_old_header_msg_t msg = rf627_protocol_old_create_header_msg(
                        recv_msg.reserved_1,
                        recv_msg.checksum,
                        kRF627_OLD_PROTOCOL_HEADER_LAST_COMMAND,
                        kRF627_OLD_PROTOCOL_HEADER_CONFIRMATION_OFF,
                        kRF627_OLD_PROTOCOL_HEADER_CONFIRMATION_MSG,
                        recv_msg.msg_options,
                        recv_msg.data_checksum,
                        recv_msg.reserved_2,
                        recv_msg.serial_number,
                        recv_msg.msg_count,
                        recv_msg.cmd,
                        0
                        );

            return rf627_protocol_old_pack_header_msg_to_packet(destination_buffer, &msg);
        }
        return 0;
    }
    return 0;
}

rfSize rf627_protocol_old_create_confirm_packet_from_response_profile_packet(
        rfUint8* destination_buffer, rfUint32 destination_buffer_size,
        rfUint8* source_buffer, rfUint32 source_buffer_size)
{
    rfSize response_packet_size =
            rf627_protocol_old_get_size_of_response_profile_header_packet();
    if (destination_buffer_size >= response_packet_size &&
            source_buffer_size >= response_packet_size)
    {
        rf627_old_stream_msg_t recv_msg =
                rf627_protocol_old_unpack_header_msg_from_profile_packet(source_buffer);

        if (recv_msg.flags & 0x80)
        {
            return 0; //TODO ACK
        }
        return 0;
    }
    return 0;
}

rf627_old_header_msg_t rf627_protocol_old_create_command_set_counters_msg(
        rf627_protocol_old_header_confirmation_t confirmation,
        rfUint32 serial_number,
        rfUint16 msg_count,
        rfUint32 profile_counter,
        rfUint32 packet_counter)
{
    rfUint16 payload_size = 0;
    if ((profile_counter != 0) || (packet_counter != 0))
            payload_size = 8;
    rf627_old_header_msg_t msg = rf627_protocol_old_create_header_msg(
                0,
                kRF627_OLD_PROTOCOL_HEADER_CHECKSUM_OFF,
                kRF627_OLD_PROTOCOL_HEADER_LAST_COMMAND,
                confirmation,
                kRF627_OLD_PROTOCOL_HEADER_COMMAND_MSG,
                0,
                0,
                0,
                serial_number,
                msg_count,
                kRF627_OLD_PROTOCOL_HEADER_CMD_SET_PROFILE_COUNTERS,
                payload_size
                );
    return msg;
}

rf627_old_header_msg_t rf627_protocol_old_create_command_periphery_send_msg(
        rf627_protocol_old_header_confirmation_t confirmation,
        rfUint32 serial_number,
        rfUint16 msg_count,
        rfUint16 input_size)
{
    rfUint16 payload_size = input_size;

    rf627_old_header_msg_t msg = rf627_protocol_old_create_header_msg(
                0,
                kRF627_OLD_PROTOCOL_HEADER_CHECKSUM_OFF,
                kRF627_OLD_PROTOCOL_HEADER_LAST_COMMAND,
                confirmation,
                kRF627_OLD_PROTOCOL_HEADER_COMMAND_MSG,
                0,
                0,
                0,
                serial_number,
                msg_count,
                kRF627_OLD_PROTOCOL_HEADER_CMD_PERIPHERY_SEND,
                payload_size
                );
    return msg;
}



//
// rf627_protocol_pack
//
rfUint32 rf627_protocol_old_pack_header_msg_to_packet(
        rfUint8* buffer,
        rf627_old_header_msg_t* msg)
{
    rfUint8 *p = buffer;
    rfUint32 result = 0;

    write_to(*p, 0, 1, msg->reserved_1);
    write_to(*p, 1, 1, msg->checksum);
    write_to(*p, 2, 1, msg->is_last);
    write_to(*p, 3, 1, msg->confirmation);
    write_to(*p, 4, 4, msg->msg_type);
    result += move_packet_n_bytes(1, &p);
    result += add_rfUint8_to_packet(msg->msg_options, &p);
    result += add_rfUint8_to_packet(msg->data_checksum, &p);
    result += add_rfUint8_to_packet(msg->reserved_2, &p);
    result += add_rfUint32_to_packet(msg->serial_number, &p, kEndianessLittle);
    result += add_rfUint16_to_packet(msg->msg_count, &p, kEndianessLittle);
    result += add_rfUint16_to_packet(msg->cmd, &p, kEndianessBig);
    result += add_rfUint16_to_packet(msg->payload_size, &p, kEndianessLittle);

    if (result == rf627_protocol_old_get_size_of_header())
        return result;
    else return 0;
}

rfSize rf627_protocol_old_pack_hello_msg_request_to_packet(
        rfUint8* buffer, rfUint32 buffer_size, rf627_old_header_msg_t* hello_msg)
{
    if(rf627_protocol_old_get_size_of_request_hello_packet() <= buffer_size)
    {
        return rf627_protocol_old_pack_header_msg_to_packet(buffer, hello_msg);
    }else
    {
        return 0;
    }
}

rfSize rf627_protocol_old_pack_read_user_params_msg_request_to_packet(
        rfUint8* buffer, rfUint32 buffer_size, rf627_old_header_msg_t* msg)
{
    if(rf627_protocol_old_get_size_of_request_hello_packet() <= buffer_size)
    {
        return rf627_protocol_old_pack_header_msg_to_packet(buffer, msg);
    }else
    {
        return 0;
    }
}

rfSize rf627_protocol_old_pack_read_factory_params_msg_request_to_packet(
        rfUint8* buffer, rfUint32 buffer_size, rf627_old_header_msg_t* msg)
{
    if(rf627_protocol_old_get_size_of_request_hello_packet() <= buffer_size)
    {
        return rf627_protocol_old_pack_header_msg_to_packet(buffer, msg);
    }else
    {
        return 0;
    }
}

rfSize rf627_protocol_old_pack_write_user_params_msg_request_to_packet(
        rfUint8* buffer, rfUint32 buffer_size, rf627_old_header_msg_t* msg)
{
    if(rf627_protocol_old_get_size_of_request_hello_packet() <= buffer_size)
    {
        return rf627_protocol_old_pack_header_msg_to_packet(buffer, msg);
    }else
    {
        return 0;
    }
}

rfSize rf627_protocol_old_pack_save_user_params_msg_request_to_packet(
        rfUint8* buffer, rfUint32 buffer_size, rf627_old_header_msg_t* msg)
{
    if(rf627_protocol_old_get_size_of_request_hello_packet() <= buffer_size)
    {
        return rf627_protocol_old_pack_header_msg_to_packet(buffer, msg);
    }else
    {
        return 0;
    }
}

rfSize rf627_protocol_old_pack_command_set_counters_to_packet(
        rfUint8* buffer, rfUint32 buffer_size, rf627_old_header_msg_t* msg)
{
    if(rf627_protocol_old_get_size_of_request_hello_packet() <= buffer_size)
    {
        return rf627_protocol_old_pack_header_msg_to_packet(buffer, msg);
    }else
    {
        return 0;
    }
}


//
// rf627_protocol_unpack
//
rf627_old_header_msg_t rf627_protocol_old_unpack_header_msg_from_packet(
        rfUint8* buffer)
{
    rfUint8 *p = buffer;

    rf627_old_header_msg_t msg = {0};

    msg.reserved_1 = read_from(*p, 0, 1);
    msg.checksum = read_from(*p, 1, 1);
    msg.is_last = read_from(*p, 2, 1);
    msg.confirmation = read_from(*p, 3, 1);
    msg.msg_type = read_from(*p, 4, 4);
    move_packet_n_bytes(1, &p);
    msg.msg_options = get_rfUint8_from_packet(&p);
    msg.data_checksum = get_rfUint8_from_packet(&p);
    msg.reserved_2 = get_rfUint8_from_packet(&p);
    msg.serial_number = get_rfUint32_from_packet(&p, kEndianessLittle);
    msg.msg_count = get_rfUint16_from_packet(&p, kEndianessLittle);
    msg.cmd = (get_rfUint8_from_packet(&p) << 8) + get_rfUint8_from_packet(&p);
    msg.payload_size = get_rfUint16_from_packet(&p, kEndianessLittle);

    return msg;
}

rf627_old_header_msg_t rf627_protocol_old_unpack_header_msg_from_hello_packet(
        rfUint8* buffer)
{
    rf627_old_header_msg_t response_header =
            rf627_protocol_old_unpack_header_msg_from_packet(buffer);
    return response_header;
}

rf627_old_device_info_t rf627_protocol_old_unpack_payload_msg_from_hello_packet(
        rfUint8* buffer)
{
    rfUint8 *p = &buffer[rf627_protocol_old_get_size_of_header()];

    rf627_old_device_info_t payload = {0};
    get_array_from_packet((rfUint8*)payload.name, &p,
                           sizeof (payload.name));
    payload.device_id = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.serial_number = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.firmware_version = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.hardware_version = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.config_version = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.fsbl_version = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.z_begin = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.z_range = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.x_smr = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.x_emr = get_rfUint32_from_packet(&p, kEndianessLittle);
    get_array_from_packet((rfUint8*)payload.reserved_0, &p,
                           sizeof (payload.reserved_0));

    payload.eth_speed = get_rfUint16_from_packet(&p, kEndianessLittle);
    get_array_from_packet((rfUint8*)payload.ip_address, &p,
                           sizeof (payload.ip_address));
    get_array_from_packet((rfUint8*)payload.net_mask, &p,
                           sizeof (payload.net_mask));
    get_array_from_packet((rfUint8*)payload.gateway_ip, &p,
                           sizeof (payload.gateway_ip));
    get_array_from_packet((rfUint8*)payload.host_ip, &p,
                           sizeof (payload.host_ip));
    payload.stream_port = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.http_port = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.service_port = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.eip_broadcast_port = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.eip_port = get_rfUint16_from_packet(&p, kEndianessLittle);
    get_array_from_packet((rfUint8*)payload.hardware_address, &p,
                           sizeof (payload.hardware_address));
    get_array_from_packet((rfUint8*)payload.reserved_1, &p,
                           sizeof (payload.reserved_1));

    payload.max_payload_size = get_rfUint32_from_packet(&p, kEndianessLittle);
    get_array_from_packet((rfUint8*)payload.reserved_2, &p,
                           sizeof (payload.reserved_2));

    payload.stream_enabled = get_rfUint8_from_packet(&p);
    payload.stream_format = get_rfUint8_from_packet(&p);
    get_array_from_packet((rfUint8*)payload.reserved_3, &p,
                           sizeof (payload.reserved_3));

    get_array_from_packet((rfUint8*)payload.reserved_4, &p,
                           sizeof (payload.reserved_4));

    return payload;
}

rf627_old_stream_msg_t rf627_protocol_old_unpack_header_msg_from_profile_packet(
        rfUint8* buffer)
{
    rfUint8 *p = &buffer[0];

    rf627_old_stream_msg_t profile_header_msg = {0};
    profile_header_msg.data_type = get_rfUint8_from_packet(&p);
    profile_header_msg.flags = get_rfUint8_from_packet(&p);
    profile_header_msg.device_type = get_rfUint16_from_packet(&p, kEndianessLittle);
    profile_header_msg.serial_number = get_rfUint32_from_packet(&p, kEndianessLittle);
    profile_header_msg.system_time = get_rfUint64_from_packet(&p, kEndianessLittle);

    profile_header_msg.proto_version_major = get_rfUint8_from_packet(&p);
    profile_header_msg.proto_version_minor = get_rfUint8_from_packet(&p);
    profile_header_msg.hardware_params_offset = get_rfUint8_from_packet(&p);
    profile_header_msg.data_offset = get_rfUint8_from_packet(&p);
    profile_header_msg.packet_count = get_rfUint32_from_packet(&p, kEndianessLittle);
    profile_header_msg.measure_count = get_rfUint32_from_packet(&p, kEndianessLittle);

    profile_header_msg.zmr = get_rfUint16_from_packet(&p, kEndianessLittle);
    profile_header_msg.xemr = get_rfUint16_from_packet(&p, kEndianessLittle);
    profile_header_msg.discrete_value = get_rfUint16_from_packet(&p, kEndianessLittle);
    get_array_from_packet((rfUint8*)profile_header_msg.reserved_0, &p,
                           sizeof (profile_header_msg.reserved_0));

    profile_header_msg.exposure_time = get_rfUint32_from_packet(&p, kEndianessLittle);
    profile_header_msg.laser_value = get_rfUint32_from_packet(&p, kEndianessLittle);
    profile_header_msg.step_count = get_rfUint32_from_packet(&p, kEndianessLittle);
    profile_header_msg.dir = get_rfUint8_from_packet(&p);
    profile_header_msg.payload_size = get_rfUint16_from_packet(&p, kEndianessLittle);
    profile_header_msg.bytes_per_point = get_rfUint8_from_packet(&p);

    return profile_header_msg;

}

rf627_old_header_msg_t rf627_protocol_old_unpack_header_msg_from_user_params_packet(
        rfUint8* buffer)
{
    rf627_old_header_msg_t response_header =
            rf627_protocol_old_unpack_header_msg_from_packet(buffer);
    return response_header;
}

rf627_old_header_msg_t rf627_protocol_old_unpack_header_msg_from_factory_params_packet(
        rfUint8* buffer)
{
    rf627_old_header_msg_t response_header =
            rf627_protocol_old_unpack_header_msg_from_packet(buffer);
    return response_header;
}

/**
 * @brief rf627_protocol_old_unpack_header_msg_from_profile_packet - unpack
 * payload msg from user_params network packet
 * @param buffer - ptr to network buffer
 * @return rf627_old_user_params_t
 */
rf627_old_user_params_msg_t rf627_protocol_old_unpack_payload_msg_from_user_params_packet(
        rfUint8* buffer)
{
    rfUint8 *p = &buffer[rf627_protocol_old_get_size_of_header()];

    rf627_old_user_params_msg_t payload = {0};

    get_array_from_packet((rfUint8*)payload.general.name, &p,
                           sizeof (payload.general.name));
    payload.general.save_log_to_spi = get_rfUint8_from_packet(&p);
    move_packet_n_bytes(sizeof (payload.general.reserved), &p);


    payload.sysmon.fpga_temp = get_rfInt16_from_packet(&p, kEndianessLittle);
    payload.sysmon.params_changed = get_rfUint8_from_packet(&p);
    payload.sysmon.sens00_temp = get_rfInt16_from_packet(&p, kEndianessLittle);
    payload.sysmon.sens00_max = get_rfInt16_from_packet(&p, kEndianessLittle);
    payload.sysmon.sens00_min = get_rfInt16_from_packet(&p, kEndianessLittle);
    payload.sysmon.sens01_temp = get_rfInt16_from_packet(&p, kEndianessLittle);
    payload.sysmon.sens01_max = get_rfInt16_from_packet(&p, kEndianessLittle);
    payload.sysmon.sens01_min = get_rfInt16_from_packet(&p, kEndianessLittle);
    payload.sysmon.sens10_temp = get_rfInt16_from_packet(&p, kEndianessLittle);
    payload.sysmon.sens10_max = get_rfInt16_from_packet(&p, kEndianessLittle);
    payload.sysmon.sens10_min = get_rfInt16_from_packet(&p, kEndianessLittle);
    payload.sysmon.sens11_temp = get_rfInt16_from_packet(&p, kEndianessLittle);
    payload.sysmon.sens11_max = get_rfInt16_from_packet(&p, kEndianessLittle);
    payload.sysmon.sens11_min = get_rfInt16_from_packet(&p, kEndianessLittle);
    move_packet_n_bytes(sizeof (payload.sysmon.reserved), &p);


    payload.rf625compat.enable = get_rfUint8_from_packet(&p);
    payload.rf625compat.tcp_port = get_rfUint16_from_packet(&p, kEndianessLittle);
    move_packet_n_bytes(sizeof (payload.rf625compat.reserved), &p);


    payload.sensor.dhs = get_rfUint8_from_packet(&p);
    payload.sensor.gain_analog = get_rfUint8_from_packet(&p);
    payload.sensor.gain_digital = get_rfUint8_from_packet(&p);
    payload.sensor.exposure = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.sensor.max_exposure = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.sensor.frame_rate = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.sensor.max_frame_rate = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.sensor.exposure_hdr_mode = get_rfUint8_from_packet(&p);
    payload.sensor.auto_exposure = get_rfUint8_from_packet(&p);
    payload.sensor.column_edr_mode = get_rfUint8_from_packet(&p);
    payload.sensor.column_exposure_div = get_rfUint8_from_packet(&p);
    payload.sensor.column_exposure_max_div = get_rfUint8_from_packet(&p);
    move_packet_n_bytes(sizeof (payload.sensor.reserved), &p);


    payload.roi.enable = get_rfUint8_from_packet(&p);
    payload.roi.active = get_rfUint8_from_packet(&p);
    payload.roi.size = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.roi.position_mode = get_rfUint8_from_packet(&p);
    payload.roi.manual_position = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.roi.auto_position = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.roi.required_profile_size = get_rfUint16_from_packet(&p, kEndianessLittle);
    move_packet_n_bytes(sizeof (payload.roi.reserved), &p);


    payload.network.speed = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.network.autonegotiation = get_rfUint8_from_packet(&p);
    get_array_from_packet((rfUint8*)payload.network.ip_address, &p,
                           sizeof (payload.network.ip_address));
    get_array_from_packet((rfUint8*)payload.network.net_mask, &p,
                           sizeof (payload.network.net_mask));
    get_array_from_packet((rfUint8*)payload.network.gateway_ip, &p,
                           sizeof (payload.network.gateway_ip));
    get_array_from_packet((rfUint8*)payload.network.host_ip, &p,
                           sizeof (payload.network.host_ip));
    payload.network.stream_port = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.network.http_port = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.network.service_port = get_rfUint16_from_packet(&p, kEndianessLittle);
    move_packet_n_bytes(sizeof (payload.network.reserved), &p);


    payload.stream.enable = get_rfUint8_from_packet(&p);
    payload.stream.format = get_rfUint8_from_packet(&p);
    payload.stream.ack = get_rfUint8_from_packet(&p);
    payload.stream.include_intensivity = get_rfUint8_from_packet(&p);
    move_packet_n_bytes(sizeof (payload.stream.reserved), &p);


    payload.image_processing.brightness_threshold = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.image_processing.filter_width = get_rfUint8_from_packet(&p);
    payload.image_processing.processing_mode = get_rfUint8_from_packet(&p);
    payload.image_processing.reduce_noise = get_rfUint8_from_packet(&p);
    payload.image_processing.frame_rate = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.image_processing.median_filter_mode = get_rfUint8_from_packet(&p);
    payload.image_processing.bilateral_filter_mode = get_rfUint8_from_packet(&p);
    payload.image_processing.peak_select_mode = get_rfUint8_from_packet(&p);
    payload.image_processing.profile_flip = get_rfUint8_from_packet(&p);
    move_packet_n_bytes(sizeof (payload.image_processing.reserved), &p);


    payload.laser.enable = get_rfUint8_from_packet(&p);
    payload.laser.level_mode = get_rfUint8_from_packet(&p);
    payload.laser.level = get_rfUint16_from_packet(&p, kEndianessLittle);
    move_packet_n_bytes(sizeof (payload.laser.reserved), &p);


    payload.inputs.preset_index = get_rfUint8_from_packet(&p);
    for(rfUint32 i = 0;
        i < sizeof (payload.inputs.params) / sizeof (payload.inputs.params[0]);
        i++)
    {
        payload.inputs.params[i].params_mask = get_rfUint16_from_packet(&p, kEndianessLittle);
        payload.inputs.params[i].in1_enable = get_rfUint8_from_packet(&p);
        payload.inputs.params[i].in1_mode = get_rfUint8_from_packet(&p);
        payload.inputs.params[i].in1_delay = get_rfUint32_from_packet(&p, kEndianessLittle);
        payload.inputs.params[i].in1_decimation = get_rfUint8_from_packet(&p);
        payload.inputs.params[i].in2_enable = get_rfUint8_from_packet(&p);
        payload.inputs.params[i].in2_mode = get_rfUint8_from_packet(&p);
        payload.inputs.params[i].in2_invert = get_rfUint8_from_packet(&p);
        payload.inputs.params[i].in3_enable = get_rfUint8_from_packet(&p);
        payload.inputs.params[i].in3_mode = get_rfUint8_from_packet(&p);
        move_packet_n_bytes(sizeof (payload.inputs.params[i].reserved), &p);
    }
    move_packet_n_bytes(sizeof (payload.inputs.reserved), &p);


    payload.outputs.out1_enable = get_rfUint8_from_packet(&p);
    payload.outputs.out1_mode = get_rfUint8_from_packet(&p);
    payload.outputs.out1_delay = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.outputs.out1_pulse_width = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.outputs.out1_invert = get_rfUint8_from_packet(&p);
    payload.outputs.out2_enable = get_rfUint8_from_packet(&p);
    payload.outputs.out2_mode = get_rfUint8_from_packet(&p);
    payload.outputs.out2_delay = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.outputs.out2_pulse_width = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.outputs.out2_invert = get_rfUint8_from_packet(&p);
    move_packet_n_bytes(sizeof (payload.outputs.reserved), &p);

    move_packet_n_bytes(sizeof (payload.reserved), &p);

    return payload;
}

/**
 * @brief rf627_protocol_old_unpack_header_msg_from_profile_packet - unpack
 * payload msg from user_params network packet
 * @param buffer - ptr to network buffer
 * @return rf627_old_user_params_t
 */
rf627_old_factory_params_msg_t rf627_protocol_old_unpack_payload_msg_from_factory_params_packet(
        rfUint8* buffer)
{
    rfUint8 *p = &buffer[rf627_protocol_old_get_size_of_header()];

    rf627_old_factory_params_msg_t payload = {0};

    payload.general.device_id               = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.general.serial                  = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.general.serial_of_pcb           = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.general.operating_time_h        = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.general.operating_time_m        = get_rfUint8_from_packet (&p);
    payload.general.operating_time_s        = get_rfUint8_from_packet (&p);
    payload.general.runtime_h               = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.general.runtime_m               = get_rfUint8_from_packet (&p);
    payload.general.runtime_s               = get_rfUint8_from_packet (&p);
    payload.general.startup_counter         = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.general.firmware_ver            = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.general.hardware_ver            = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.general.customer_id             = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.general.pl_system_clk           = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.general.base_z                  = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.general.range_z                 = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.general.range_x_start           = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.general.range_x_end             = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.general.pixels_divider          = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.general.profiles_divider        = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.general.fsbl_version            = get_rfUint32_from_packet(&p, kEndianessLittle);
    get_array_from_packet((rfUint8*)payload.general.oem_device_name, &p,
                           sizeof (payload.general.oem_device_name));
    move_packet_n_bytes(sizeof (payload.general.reserved), &p);

    get_array_from_packet((rfUint8*)payload.sensor.name, &p,
                           sizeof (payload.sensor.name));
    payload.sensor.width                    = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.sensor.height                   = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.sensor.pixel_clock              = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.sensor.black_odd_lines          = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.sensor.black_even_lines         = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.sensor.frame_cycle_const_part   = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.sensor.frame_cycle_per_line_part= get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.sensor.frame_rate_or_exposure   = get_rfUint8_from_packet (&p);
    payload.sensor.min_exposure             = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.sensor.image_flipping           = get_rfUint8_from_packet (&p);
    payload.sensor.max_exposure             = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.sensor.edr_point1_value         = get_rfUint8_from_packet (&p);
    payload.sensor.edr_point2_value         = get_rfUint8_from_packet (&p);
    payload.sensor.edr_point1_pos           = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.sensor.edr_point2_pos           = get_rfUint16_from_packet(&p, kEndianessLittle);
    move_packet_n_bytes(sizeof (payload.sensor.reserved), &p);
    for(rfUint32 i = 0;
        i < sizeof (payload.sensor.init_regs) / sizeof (payload.sensor.init_regs[0]);
        i++)
    {
        payload.sensor.init_regs[i].addr    = get_rfUint16_from_packet(&p, kEndianessLittle);
        payload.sensor.init_regs[i].value   = get_rfUint16_from_packet(&p, kEndianessLittle);
    }

    get_array_from_packet((rfUint8*)payload.network.mac, &p,
                           sizeof (payload.network.mac));
    payload.network.eip_vendor_id           = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.network.eip_device_type         = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.network.force_autoneg_time      = get_rfUint8_from_packet (&p);
    move_packet_n_bytes(sizeof (payload.network.reserved), &p);

    payload.laser.wave_length               = get_rfUint16_from_packet(&p, kEndianessLittle);				//Длина волны в нм
    payload.laser.koeff1                    = get_rfUint8_from_packet (&p);						//Коээфициент крутизны регулирования отпределяется как Koeff1/128
    payload.laser.koeff2                    = get_rfUint8_from_packet (&p);
    payload.laser.min_value                 = get_rfUint32_from_packet(&p, kEndianessLittle);								//Значение, при котором лазер зажигается
    payload.laser.max_value                 = get_rfUint32_from_packet(&p, kEndianessLittle);								//Максимальное допустимое значение
    payload.laser.enable_mode_change        = get_rfUint8_from_packet (&p);			//Разрешение изменения режима работы лазера: 0 - запрещено, 1 - разрешено
    move_packet_n_bytes(sizeof (payload.laser.reserved), &p);


    payload.inputs.in1_min_delay            = get_rfUint16_from_packet(&p, kEndianessLittle);				//Минимальная задержка в нс
    payload.inputs.in1_max_delay            = get_rfUint32_from_packet(&p, kEndianessLittle);				//Максимальная задержка в нс
    payload.inputs.max_divider_in1          = get_rfUint16_from_packet(&p, kEndianessLittle);				//Максимальное значение делителя частоты кадров
    payload.inputs.min_divider_in1          = get_rfUint16_from_packet(&p, kEndianessLittle);				//Минимальное значение делителя частоты кадров
    move_packet_n_bytes(sizeof (payload.inputs.reserved), &p);

    payload.outputs.out1_min_delay          = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.outputs.out1_max_delay          = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.outputs.out1_min_pulse_width    = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.outputs.out1_max_pulse_width    = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.outputs.out2_min_delay          = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.outputs.out2_max_delay          = get_rfUint32_from_packet(&p, kEndianessLittle);
    payload.outputs.out2_min_pulse_width    = get_rfUint16_from_packet(&p, kEndianessLittle);
    payload.outputs.out2_max_pulse_width    = get_rfUint32_from_packet(&p, kEndianessLittle);
    move_packet_n_bytes(sizeof (payload.outputs.reserved), &p);

    payload.profiles.max_dump_size          = get_rfUint32_from_packet(&p, kEndianessLittle);
    move_packet_n_bytes(sizeof (payload.profiles.reserved), &p);

    return payload;
}





/**
 * @brief rf627_protocol_old_unpack_header_msg_from_profile_packet - unpack
 * payload msg from user_params network packet
 * @param buffer - ptr to network buffer
 * @return rf627_old_user_params_t
 */
rfUint32 rf627_protocol_old_pack_payload_msg_to_command_set_counter_packet(
        rfUint8* buffer, rfUint32 profile_counter, rfUint32 packet_counter)
{
    rfUint8 *buf = &buffer[0];

    add_rfUint32_to_packet(profile_counter, &buf, kEndianessLittle);

    add_rfUint32_to_packet(packet_counter, &buf, kEndianessLittle);

    return RF627_PROTOCOL_OLD_COMMAND_SET_COUNTERS_PAYLOAD_PACKET_SIZE;
}


rfUint32 rf627_protocol_old_pack_payload_msg_to_command_periphery_send_packet(
        rfUint8* buffer, rfUint16 input_size, void* payload)
{
    rfUint8 *buf = &buffer[0];

    for(rfUint16 i = 0; i < input_size; i++)
    {
        add_rfByte_to_packet(((rfByte*)payload)[i], &buf);
    }

    return input_size;
}





rfUint32 srvc_proto_627_old_get_serial_number_from_message(uint8_t* message, rfUint32 message_size)
{
    if(message_size > sizeof (rf627_old_header_msg_t))
    {
        return ((rf627_old_header_msg_t*)message)->serial_number;
    }
    return 0;
}

rfUint32 srvc_proto_627_get_counter_from_message(uint8_t* message, rfUint32 message_size)
{
    if(message_size > sizeof (rf627_old_header_msg_t))
    {
        return ((rf627_old_header_msg_t*)message)->msg_count;
    }
    return 0;
}

rfUint32 srvc_proto_627_get_payload_from_message(uint8_t* message, rfUint32 message_size,
                                  rfUint8* buffer, rfUint32 buffer_size)
{
//    if(message_size > sizeof (rf627_old_header_msg_t))
//    {
//        if (((rf627_old_header_msg_t*)message)->module == MID_rf627_old_UserParams)
//        {
//            if(message_size - sizeof (rf627_old_service_msg_t) <= buffer_size)
//            {
//                memcpy(buffer, &message[sizeof (rf627_old_service_msg_t)],
//                        message_size - sizeof (rf627_old_service_msg_t));
//                return message_size - sizeof (rf627_old_service_msg_t);
//            }
//            return 0;
//        }
//        return 0;
//    }
//    return 0;

}

rfBool rf627_protocol_send_packet_by_udp(
        void* s, rfUint8* msg, rfUint32 size, rfUint32 ip_addr, rfUint16 port,
        rfUint32 payload_length, void* payload)
{
    rfUint8* TX = memory_platform.rf_calloc(1, size + payload_length);

    memory_platform.rf_memcpy(TX, msg, size);

    if (payload_length > 0 && payload)
        memory_platform.rf_memcpy(&TX[size], payload, payload_length);

    rfInt32 nret = 0;
    nret = network_platform.network_methods.
            send_udp_data(s, TX, size + payload_length, ip_addr, port);

    memory_platform.rf_free(TX);
    return ( (rfUint32)nret == size + payload_length);
}



rf627_old_header_msg_t rf627_protocol_old_create_save_user_params_msg_request(rf627_protocol_old_header_confirmation_t confirmation, rfUint32 serial_number, rfUint16 msg_count)
{
    rf627_old_header_msg_t msg = rf627_protocol_old_create_header_msg(
                0,
                kRF627_OLD_PROTOCOL_HEADER_CHECKSUM_OFF,
                kRF627_OLD_PROTOCOL_HEADER_LAST_COMMAND,
                confirmation,
                kRF627_OLD_PROTOCOL_HEADER_COMMAND_MSG,
                0,
                0,
                0,
                serial_number,
                msg_count,
                kRF627_OLD_PROTOCOL_HEADER_CMD_SAVE_PARAMS,
                0
                );
    return msg;
}
