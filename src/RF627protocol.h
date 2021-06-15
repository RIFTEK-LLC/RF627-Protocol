﻿#ifndef RF627_PROTOCOL_H
#define RF627_PROTOCOL_H

#include "platform_types.h"


/* RF627_old - Service Message
 +--------+---------------+-------------+--------------------------------------+
 | Index  | Function      | Size, bytes | Description                          |
 |--------|---------------|-------------|--------------------------------------|
 | 0      | Msg type      | 1           | Bits 7-4 (Message type) :            |
 |        |               |             |  -b0001: command;                    |
 |        |               |             |  -b0010: confirmation of the command;|
 |        |               |             |  -b0011: response to the command;    |
 |        |               |             | Bit 3 (request for confirmation of   |
 |        |               |             |        response or command) :        |
 |        |               |             |  -b0: confirmation is not required;  |
 |        |               |             |  -b1: confirmation is required;      |
 |        |               |             | Bit 2 (is a sign of the last command |
 |        |               |             |        or response ) :               |
 |        |               |             |  -b0: command/response is not last;  |
 |        |               |             |  -b1: command/response is last;      |
 |        |               |             | Bit 1 (a sign of the presence of a   |
 |        |               |             |        checksum in the message       |
 |        |               |             |        parameters (in Index 2)) :    |
 |        |               |             |  -b0 - on checksum;                  |
 |        |               |             |  -b1 - off checksum;                 |
 |        |               |             | bit 0 (is the reserve)               |
 +--------+---------------+-------------+--------------------------------------+
 | 1      | Msg options   | 1           | Not used yet                         |
 +--------+---------------+-------------+--------------------------------------+
 | 2      | Data checksum | 1           | Data Area Checksum                   |
 +--------+---------------+-------------+--------------------------------------+
 | 3      | Reserve       | 1           | Not used yet                         |
 +--------+---------------+-------------+--------------------------------------+
 | 4      | Device id     | 4           | Unique identifier of the device      |
 |        |               |             | (SCANNER SERIAL NUMBER) to which     |
 |        |               |             | the message was sent. May be         |
 |        |               |             | broadcast: 0xFFFFFFFF. When sending a|
 |        |               |             | message or confirmation by the       |
 |        |               |             | scanner, contains the identifier of  |
 |        |               |             | the scanner.                         |
 +--------+---------------+-------------+--------------------------------------+
 | 8      | Unique msg id | 2           | The msg counter (for confirmation)   |
 |        |               |             | must be unique from message to       |
 |        |               |             | message, the repetition period of    |
 |        |               |             | 65536 messages is quite sufficient   |
 |        |               |             | for work.                            |
 +--------+---------------+-------------+--------------------------------------+
 | 10     | Command id    | 2           | Command ID - specific device command |
 |        |               |             | (consist of ModulId and SubCommandId)|
 +--------+---------------+-------------+--------------------------------------+
 | 12     | Data size     | 2           | Payload data size                    |
 +--------+---------------+-------------+--------------------------------------+
 | 14     | Payload       | N           | Command attributes or response data. |
 | ..     |               |             | In the case of sending a command, the|
 | ..     |               |             | field contains attributes (data that |
 | ..     |               |             | must be applied). In the case of     |
 | ..     |               |             | confirmation or response, the data   |
 | 14+N   |               |             | requested by the team.               |
 +--------+---------------+-------------+--------------------------------------+
 */

/**
 * @enum rf627_old_msg_type_t
 * @brief is a enum representing Message type (Index 0 Bits 7-4)
 */
typedef enum
{
    MSG_rf627_old_Command = 0x01, /**< command for */
    MSG_rf627_old_Ack     = 0x02, /**< command for */
    MSG_rf627_old_Answer  = 0x03  /**< command for */
} rf627_old_msg_type_t;

/**
 * @brief DEVICE_ID_ALL - Broadcast device identifier: 0xFFFFFFFF.
 */
#define DEVICE_ID_ALL 0xffffffff

/**
 * @brief RF627_OLD_HEADER_SIZE - Header size is 14 bytes
 */
#define RF627_PROTOCOL_OLD_HEADER_SIZE 14

/**
 * @brief RF627_PROTOCOL_OLD_HELLO_RESPONSE_PACKET_SIZE - Packet size is 524 bytes.
 */
#define RF627_PROTOCOL_OLD_HELLO_RESPONSE_PACKET_SIZE 524

/**
 * @brief RF627_PROTOCOL_OLD_PROFILE_RESPONSE_HEADER_SIZE - Packet size is 524 bytes.
 */
#define RF627_PROTOCOL_OLD_PROFILE_RESPONSE_HEADER_SIZE 64

/**
 * @brief RF627_PROTOCOL_OLD_USER_RESPONSE_PACKET_SIZE - Packet size is 1400 bytes.
 */
#define RF627_PROTOCOL_OLD_USER_RESPONSE_PACKET_SIZE 1400

/**
 * @brief RF627_PROTOCOL_OLD_FACTORY_RESPONSE_PACKET_SIZE - Packet size is 1120 bytes.
 */
#define RF627_PROTOCOL_OLD_FACTORY_RESPONSE_PACKET_SIZE 1120

/**
 * @brief RF627_PROTOCOL_OLD_USER_REQUEST_PAYLOAD_PACKET_SIZE - Packet size is 1400 bytes.
 */
#define RF627_PROTOCOL_OLD_USER_REQUEST_PAYLOAD_PACKET_SIZE 1400

/**
 * @brief RF627_PROTOCOL_OLD_USER_REQUEST_PAYLOAD_PACKET_SIZE - Packet size is 83 bytes.
 */
#define RF627_PROTOCOL_OLD_USER_SENSOR_REQUEST_PAYLOAD_PACKET_SIZE 83

/**
 * @brief RF627_PROTOCOL_OLD_USER_REQUEST_PAYLOAD_PACKET_SIZE - Packet size is 1400 bytes.
 */
#define RF627_PROTOCOL_OLD_FACTORY_REQUEST_PAYLOAD_PACKET_SIZE 1120

/**
 * @brief RF627_PROTOCOL_OLD_COMMAND_SET_COUNTERS - Payload size is 8 bytes.
 */
#define RF627_PROTOCOL_OLD_COMMAND_SET_COUNTERS_PAYLOAD_PACKET_SIZE 8

/**
 * @enum rf627_protocol_old_header_checksum_t
 * @brief is a enum representing of a sign of the presence of a checksum in the
 * message parameters (Bit 1 in Index 0)
 */
typedef enum
{
    kRF627_OLD_PROTOCOL_HEADER_CHECKSUM_OFF = 0,
    kRF627_OLD_PROTOCOL_HEADER_CHECKSUM_ON  = 1,
}
rf627_protocol_old_header_checksum_t;

/**
 * @enum rf627_protocol_old_header_last_command_t
 * @brief is a enum representing of a sign of the last command or response
 * (Bit 2 in Index 0)
 */
typedef enum
{
    kRF627_OLD_PROTOCOL_HEADER_NOT_LAST_COMMAND = 0,
    kRF627_OLD_PROTOCOL_HEADER_LAST_COMMAND  = 1,
}
rf627_protocol_old_header_last_command_t;

/**
 * @enum rf627_protocol_old_header_last_command_t
 * @brief is a enum representing of the necessity for confirmation of request
 * for confirmation of response or command (Bit 3 in Index 0)
 */
typedef enum
{
    kRF627_OLD_PROTOCOL_HEADER_CONFIRMATION_OFF = 0,
    kRF627_OLD_PROTOCOL_HEADER_CONFIRMATION_ON  = 1,
}
rf627_protocol_old_header_confirmation_t;

/**
 * @enum rf627_protocol_old_header_msg_type_t
 * @brief is a enum representing of the Message type (Bits 7-4 in Index 0)
 */
typedef enum
{
    kRF627_OLD_PROTOCOL_HEADER_COMMAND_MSG       = 1,
    kRF627_OLD_PROTOCOL_HEADER_CONFIRMATION_MSG  = 2,
    kRF627_OLD_PROTOCOL_HEADER_RESPONSE_MSG      = 3,
}
rf627_protocol_old_header_msg_type_t;

/**
 * @enum rf627_old_module_id_t
 * @brief is a enum representing of first byte from commands (Index 10)
 */
typedef enum
{
    kRF627_OLD_PROTOCOL_HEADER_MID_FACTORY_PARAMS   = 0x50, /**< command for get Factory Params */
    kRF627_OLD_PROTOCOL_HEADER_MID_USER_PARAMS      = 0x5e, /**< command for get User Params */
    kRF627_OLD_PROTOCOL_HEADER_MID_SENSOR_DRIVER    = 0x51, /**< command for */
    kRF627_OLD_PROTOCOL_HEADER_MID_CALIBRATION_CTRL = 0x52, /**< command for */
    kRF627_OLD_PROTOCOL_HEADER_MID_FRAME_CAPTURE    = 0x53, /**< command for */
    kRF627_OLD_PROTOCOL_HEADER_MID_QSPI_DRIVER      = 0x5a, /**< command for */
    kRF627_OLD_PROTOCOL_HEADER_MID_DUMP_CAPTURE     = 0x5c  /**< command for */
}
rf627_old_header_module_id_t;

/**
 * @enum rf627_protocol_old_header_cmd_t
 * @brief is a enum representing identifiers of device commands (Index 10)
 */
typedef enum
{
    // MID_USER_PARAMS (0x5e)
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_DEVICE_INFO         = 0x5e00,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_GENERAL_PARAMS      = 0x5e01,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_SYS_MON             = 0x5e03,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_RF625_COMPATIBIL    = 0x5e05,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_SENSOR              = 0x5e07,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_ROI                 = 0x5e09,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_NETWORK             = 0x5e0b,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_STREAM              = 0x5e0d,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_PROCESSING          = 0x5e0f,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_LASER               = 0x5e11,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_INPUTS              = 0x5e13,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_OUTPUTS             = 0x5e15,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_LOG_ITEM            = 0x5e17,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_LOG_ITEM_COUNT      = 0x5e18,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_PROFILE_VIEW        = 0x5e19,

    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_USER_GENERAL_PARAMS      = 0x5e02,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_USER_SYS_MON             = 0x5e04,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_USER_RF625_COMPATIBIL    = 0x5e06,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_USER_SENSOR              = 0x5e08,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_USER_ROI                 = 0x5e0a,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_USER_NETWORK             = 0x5e0c,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_USER_STREAM              = 0x5e0e,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_USER_PROCESSING          = 0x5e10,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_USER_LASER               = 0x5e12,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_USER_INPUTS              = 0x5e14,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_USER_OUTPUTS             = 0x5e16,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_PROFILE_VIEW             = 0x5e1a,


    // MID_FACTORY_PARAMS (0x50)
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_FACTORY_PARAMS           = 0x5000,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_USER_PARAMS              = 0x5002,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_DEFAULT_FACTORY_PARAMS   = 0x5014,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_DEFAULT_USER_PARAMS      = 0x5015,

    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_FACTORY_PARAMS           = 0x5001,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_USER_PARAMS              = 0x5003,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_START_UP_COUNTER         = 0x5020,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_OPERATING_TIME           = 0x5021,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_FACTORY_OEM_DEVICE_NAME  = 0x502B,

    kRF627_OLD_PROTOCOL_HEADER_CMD_LOAD_DEFAULT_PARAMS          = 0x5013,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SAVE_PARAMS                  = 0x5010,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SAVE_AS_DEFAULT_PARAMS       = 0x5011,

    kRF627_OLD_PROTOCOL_HEADER_CMD_RESET                        = 0x5012,


    // MID_SENSOR_DRIVER (0x51)
    kRF627_OLD_PROTOCOL_HEADER_CMD_READ_SENSOR_DRIVER_REGISTER  = 0x5107,
    kRF627_OLD_PROTOCOL_HEADER_CMD_WRITE_SENSOR_DRIVER_REGISTER = 0x5187,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_SENSOR_DRIVER_BLACK_ODD  = 0x51a0,
//  kRF627_OLD_PROTOCOL_HEADER_CMD_SENSOR_DRIVER_SET_BLACK_ODD  = 0x51a1,


    // MID_CALIBRATION_CTRL (0x52)
    kRF627_OLD_PROTOCOL_HEADER_CMD_WRITE_CALIB_FILE_DATA        = 0x5210,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_CALIB_FILE_CRC16         = 0x5112,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SAVE_CALIB_FILE              = 0x5120,


    // MID_FRAME_CAPTURE (0x53)
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_CAPTURE_FRAME            = 0x5310,


    // MID_QSPI_DRIVER (0x5a)
    kRF627_OLD_PROTOCOL_HEADER_CMD_ERASE_FLASH_MEMORY           = 0x5a00,
    kRF627_OLD_PROTOCOL_HEADER_CMD_READ_FLASH_MEMORY            = 0x5a10,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_FLASH_CRC16              = 0x5a12,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_FLASH_SECTOR             = 0x5a23,
    kRF627_OLD_PROTOCOL_HEADER_CMD_WRITE_FIRMWARE_TO_FLASH      = 0x5a20,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_FIRMWARE_CRC16_FROM_FLASH= 0x5a21,
    kRF627_OLD_PROTOCOL_HEADER_CMD_SAVE_FIRMWARE_TO_FLASH       = 0x5a22,


    // MID_QSPI_DRIVER (0x5c)
    kRF627_OLD_PROTOCOL_HEADER_CMD_SET_PROFILE_COUNTERS         = 0x5c10,
    kRF627_OLD_PROTOCOL_HEADER_CMD_START_PROFILE                = 0x5c04,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_PROFILE                  = 0x5c05,
    kRF627_OLD_PROTOCOL_HEADER_CMD_START_PROFILE_DUMP           = 0x5c20,
    kRF627_OLD_PROTOCOL_HEADER_CMD_STOP_PROFILE_DUMP            = 0x5c21,
    kRF627_OLD_PROTOCOL_HEADER_CMD_GET_PROFILE_DUMP             = 0x5c22,


    // CID_PERIPHERY_SEND (0x80)
    kRF627_OLD_PROTOCOL_HEADER_CMD_PERIPHERY_SEND               = 0x8010,
    kRF627_OLD_PROTOCOL_HEADER_CMD_PERIPHERY_REQUEST            = 0x8011
}
rf627_protocol_old_header_cmd_t;


typedef struct
{
    rfUint8                                  reserved_1;    //: 1;
    rf627_protocol_old_header_checksum_t     checksum;      //: 1;
    rf627_protocol_old_header_last_command_t is_last;       //: 1;
    rf627_protocol_old_header_confirmation_t confirmation;  //: 1;
    rf627_protocol_old_header_msg_type_t     msg_type;      //: 4;
    rfUint8                                  msg_options;   //: 8;
    rfUint8                                  data_checksum; //: 8;
    rfUint8                                  reserved_2;    //: 8;
    rfUint32                                 serial_number; //: 32;
    rfUint16                                 msg_count;     //: 16;
    rf627_protocol_old_header_cmd_t          cmd;           //: 16;
    rfUint16                                 payload_size;  //: 16;
}
rf627_old_header_msg_t;


typedef struct
{
    rfChar        name[64];
    rfUint16    device_id;
    rfUint32    serial_number;
    rfUint32    firmware_version;
    rfUint32    hardware_version;
    rfUint32    config_version;
    rfUint32    fsbl_version;
    rfUint32    z_begin;
    rfUint32    z_range;
    rfUint32    x_smr;
    rfUint32    x_emr;
    rfUint8     reserved_0[36];

    rfUint16    eth_speed;
    rfUint8     ip_address[4];
    rfUint8     net_mask[4];
    rfUint8     gateway_ip[4];
    rfUint8     host_ip[4];
    rfUint16    stream_port;
    rfUint16    http_port;
    rfUint16    service_port;
    rfUint16    eip_broadcast_port;
    rfUint16    eip_port;
    rfUint8     hardware_address[6];
    rfUint8     reserved_1[26];

    rfUint32    max_payload_size;
    rfUint8     reserved_2[32];

    rfUint8     stream_enabled;
    rfUint8     stream_format;
    rfUint8     reserved_3[32];

    rfUint8     reserved_4[256];
}
rf627_old_device_info_t;

typedef struct
{
    struct
    {
        rfChar        name[64];
        rfUint8     save_log_to_spi;
        rfUint8		reserved[127];
    }general;

    struct
    {
        rfInt16		fpga_temp;
        rfUint8		params_changed;			//Параметры были изменены, но не сохранены: 1 - factory, 2 - user, 3 - factory & user
        rfInt16		sens00_temp;
        rfInt16		sens00_max;
        rfInt16		sens00_min;
        rfInt16		sens01_temp;
        rfInt16		sens01_max;
        rfInt16		sens01_min;
        rfInt16		sens10_temp;
        rfInt16		sens10_max;
        rfInt16		sens10_min;
        rfInt16		sens11_temp;
        rfInt16		sens11_max;
        rfInt16		sens11_min;
        rfUint8		reserved[55];
    }sysmon;

    struct
    {
        rfUint8		enable;
        rfUint16	tcp_port;
        rfUint8		reserved[32];
    }rf625compat;

    struct
    {
        rfUint8		dhs;
        rfUint8		gain_analog;
        rfUint8		gain_digital;
        rfUint32	exposure;
        rfUint32	max_exposure;
        rfUint32	frame_rate;
        rfUint32	max_frame_rate;
        rfUint8     exposure_hdr_mode;
        rfUint8     auto_exposure;
        rfUint8		column_edr_mode;
        rfUint8		column_exposure_div;
        rfUint8     column_exposure_max_div;
        rfUint8		reserved[59];
    }sensor;

    struct
    {
        rfUint8		enable;
        rfUint8		active;
        rfUint16	size;
        rfUint8		position_mode;
        rfUint16	manual_position;
        rfUint16	auto_position;
        rfUint16	required_profile_size;
        rfUint8		reserved[80];
    }roi;

    struct
    {
        rfUint16	speed;
        rfUint8		autonegotiation;
        rfUint8    ip_address[4];
        rfUint8    net_mask[4];
        rfUint8    gateway_ip[4];
        rfUint8    host_ip[4];
        rfUint16    stream_port;
        rfUint16    http_port;
        rfUint16    service_port;
    //    rfUint16    eip_broadcast_port;
    //    rfUint16    eip_port;
        rfUint8		reserved[68];
    }network;

    struct
    {
        rfUint8		enable;
        rfUint8		format;
        rfUint8		ack;
        rfUint8     include_intensivity;
        rfUint8		reserved[31];
    }stream;

    struct
    {
        rfUint32	brightness_threshold;
        rfUint8		filter_width;
        rfUint8		processing_mode;
        rfUint8		reduce_noise;
        rfUint32    frame_rate;
        rfUint8		median_filter_mode;
        rfUint8		bilateral_filter_mode;
        rfUint8     peak_select_mode;
        rfUint8     profile_flip;
        rfUint8		reserved[56];
    }image_processing;

    struct
    {
        rfUint8		enable;
        rfUint8		level_mode;
        rfUint16	level;
        rfUint8		reserved[32];
    }laser;

    struct
    {
        rfUint8                 preset_index;
        struct
        {
            rfUint16    params_mask;
            rfUint8		in1_enable;
            rfUint8		in1_mode;
            rfUint32	in1_delay;
            rfUint8		in1_decimation;
            rfUint8		in2_enable;
            rfUint8		in2_mode;
            rfUint8		in2_invert;
            rfUint8		in3_enable;
            rfUint8		in3_mode;
            rfUint8		reserved[12];
        }params[12];
        rfUint8                 reserved[32];
    }inputs;

    struct
    {
        rfUint8		out1_enable;
        rfUint8		out1_mode;
        rfUint32	out1_delay;
        rfUint32	out1_pulse_width;
        rfUint8		out1_invert;
        rfUint8		out2_enable;
        rfUint8		out2_mode;
        rfUint32	out2_delay;
        rfUint32	out2_pulse_width;
        rfUint8		out2_invert;
        rfUint8		reserved[32];
    }outputs;

    rfUint8                   reserved[283];
}rf627_old_user_params_msg_t;

typedef struct
{
/*-------Общие параметры устройства-----------------------*/
    struct
    {
        rfUint16					device_id;			//Идентификатор типа сканера
        rfUint32					serial;				//Серийный номер сканера
        rfUint32					serial_of_pcb;		//Серийный номер электроники
        rfUint32					operating_time_h;	//Наработка сканера, часов
        rfUint8						operating_time_m;	//Наработка сканера, минут
        rfUint8						operating_time_s;	//Наработка сканера, секунд
        rfUint32					runtime_h;			//Время работы после запуска, часов
        rfUint8						runtime_m;	        //Время работы после запуска, минут
        rfUint8						runtime_s;	        //Время работы после запуска, секунд
        rfUint32					startup_counter;    //Количество запусков сканера
        rfUint32					firmware_ver;		//Версия прошивки
        rfUint32					hardware_ver;		//Версия аппаратного обеспечения
        rfUint32					customer_id;
        rfUint32					pl_system_clk;		//Системная тактовая для PL - частота AXI в Гц
        rfUint32					base_z;
        rfUint32					range_z;
        rfUint32					range_x_start;
        rfUint32					range_x_end;
        rfUint16					pixels_divider;
        rfUint16					profiles_divider;
        rfUint32					fsbl_version;		//Версия загрузчика
        rfChar                      oem_device_name[16];
        rfUint8						reserved[76];
    }general;
/*-------Параметры установленной матрицы-------------------*/
    struct
    {
        rfChar						name[32];					//Имя матрицы - для отображения
        rfUint16					width;						//Количество пикселов по горизонтали
        rfUint16					height;						//Количество пикселов но вертикали
        rfUint32					pixel_clock;					//Пиксельная частота в Гц
        rfUint16					black_odd_lines;
        rfUint16					black_even_lines;
        rfUint32					frame_cycle_const_part;
        rfUint32					frame_cycle_per_line_part;
        rfUint8						frame_rate_or_exposure;		//Селектор по чем настраивать матрицу - по частоте кадров или экспозиции: 0 - по частоте, 1 - по экспозиции
        rfUint32					min_exposure;				//Минимальное время экспозиции в нс.
        rfUint8						image_flipping;				//Режим отражения изображения: 0 - без отражения, 1 - по X, 2 - по Y, 3 - и по X и по Y
        rfUint32					max_exposure;				//Максимальное время экспозиции, заданное при настройке сканера
        rfUint8						edr_point1_value;				//Значение напряжения (в условных единицах 0..63) в 1-й точке излома прямой накопления (стр.30-31 даташита CMV300)
        rfUint8						edr_point2_value;				//Значение напряжения (в условных единицах 0..63) во 2-й точке излома прямой накопления (стр.30-31 даташита CMV300)
        rfUint16					edr_point1_pos;				//Положение в 1/1000 точки относительно начала экспозиции, т.е. 0 - одновременно с началом экспозиции, 999 - сразу в конце
        rfUint16					edr_point2_pos;				//Положение в 1/1000 точки относительно начала экспозиции, т.е. 0 - одновременно с началом экспозиции, 999 - сразу в конце
        rfUint8						reserved[113];
        struct
        {
            rfUint16 addr;
            rfUint16 value;
        }init_regs[64];               //Структура с параметрами инициализации регистров матрицы
    }sensor;
/*-------Параметры сетевого подключения-------------------*/
    struct
    {
        rfUint8						mac[6];
        rfUint16					eip_vendor_id;
        rfUint16					eip_device_type;
        rfUint8						force_autoneg_time;			//Количество секунд, через которое сканер установит автосогласование принудительно в случае отсутствия связи по Ethernet
        rfUint8						reserved[31];
    }network;
/*-------Параметры управления лазером----------------------*/
    struct
    {
        rfUint16					wave_length;				//Длина волны в нм
        rfUint8						koeff1;					//Коээфициент крутизны регулирования отпределяется как Koeff1/128
        rfUint8						koeff2;
        rfUint32					min_value;				//Значение, при котором лазер зажигается
        rfUint32					max_value;				//Максимальное допустимое значение
        rfUint8						enable_mode_change;		//Разрешение изменения режима работы лазера: 0 - запрещено, 1 - разрешено
        rfUint8						reserved[31];
    }laser;
/*------------Параметры входных каналов--------------------*/
    struct
    {
        rfUint16					in1_min_delay;			//Минимальная задержка в нс
        rfUint32					in1_max_delay;			//Максимальная задержка в нс
        rfUint16					max_divider_in1;			//Максимальное значение делителя частоты кадров
        rfUint16					min_divider_in1;			//Минимальное значение делителя частоты кадров
        rfUint8						reserved[62];
    }inputs;
/*------------Параметры выходных каналов-------------------*/
    struct
    {
        rfUint16					out1_min_delay;
        rfUint32					out1_max_delay;
        rfUint16					out1_min_pulse_width;
        rfUint32					out1_max_pulse_width;
        rfUint16					out2_min_delay;
        rfUint32					out2_max_delay;
        rfUint16					out2_min_pulse_width;
        rfUint32					out2_max_pulse_width;
        rfUint8						reserved[32];
    }outputs;
    /*------------Параметры обработки профилей-----------------*/
    struct
    {
        rfUint32					max_dump_size;
        rfUint8						reserved[60];
    }profiles;
    /*------------Параметры протокола EthernetIP---------------*/
    struct
    {
        struct
        {
            rfUint16				vendor_iD;				// Attribute 1: Vendor ID - идентификационный номер производителя устройства
            rfUint16				device_type;				// Attribute 2: Device Type - тип устройства, который определяет его область использования
            rfUint16				product_code;			// Attribute 3: Product Code - идентифицирует номер конкретного продукта
            struct
            {	uint8_t					major_rev;			// Attribute 4: Revision	USINT Major
                rfUint8					minor_rev;			//							USINT Minor
            }revision;										// Структура, хранящая EIP-версию девайса
        }identity;

        struct
        {
            rfUint32				config_capability;		// Attribute 2: Данный атрибут описывает поддержку устройством дополнительных возможностей конфигурации сети
            struct
            {	uint16_t				path_size;			// Path size in 16 bit words (path_size * 16 bit)
                rfUint16				classId;			// Class ID of the linked object
                rfUint16				instance_number;		// Requested Instance Number of the linked object
                rfUint16				attribute_number;	// Requested Attribute Number of the linked object
            }phyLinkObject;									// Attribute 4: Этот атрибут идентифицирует объект, связанный с базовым физическим интерфейсом связи (Ethernet Link Object)
        }tcpInterface;

        rfUint8						intrf_type;				//Type of rfInterface: twisted pair, fiber, rfInternal, etc
        struct
        {	uint16_t					capability_bits;
            rfUint8						speed_dup_count;
            struct
            {
                rfUint16					speed;
                rfUint8						duplex;
            }speedDuplex[4];
        }intrfCapability;									//Path to physical link object

        rfUint8						reserved[44];
    }eip;
    /*-------Резерв--------------------------------------------*/
    rfUint8							reserved[167];
    /*---------------------------------------------------------*/
}rf627_old_factory_params_msg_t;

typedef struct{
    struct{
        rfUint32 H;
        rfUint8 M;
        rfUint8 S;
    }Time;
    rfUint8 ModuleID;
    rfUint8 EventID;
    rfChar String[128];
}rf627_old_log_record_t;


typedef struct
{
    rfUint8     data_type;
    rfUint8     flags;
    rfUint16    device_type;
    rfUint32    serial_number;
    rfUint64    system_time;

    rfUint8     proto_version_major;
    rfUint8     proto_version_minor;
    rfUint8     hardware_params_offset;
    rfUint8     data_offset;
    rfUint32    packet_count;
    rfUint32    measure_count;

    rfUint16    zmr;
    rfUint16    xemr;
    rfUint16    discrete_value;
    rfUint8     reserved_0[14];

    rfUint32    exposure_time;
    rfUint32    laser_value;
    rfUint32    step_count;
    rfUint8     dir;
    rfUint16    payload_size;
    rfUint8     bytes_per_point;
}
rf627_old_stream_msg_t;




//
// rf627_protocol_get_size
// response
/**
 * @brief rf627_protocol_get_size_of_old_header
 * @return Header size for rf627old
 */
rfUint32 rf627_protocol_old_get_size_of_header();
/**
 * @brief rf627_protocol_get_size_of_old_response_hello_packet
 * @return Size of response hello packet from rf627old
 */
rfUint32 rf627_protocol_old_get_size_of_response_hello_packet();
/**
 * @brief rf627_protocol_old_get_size_of_request_read_params_msg
 * @return Size of request hello packet for rf627old
 */
rfUint32 rf627_protocol_old_get_size_of_request_read_user_params_packet();

//
// rf627_protocol_get_size
// request
/**
 * @brief rf627_protocol_get_size_of_old_request_hello_packet
 * @return Size of request hello packet for rf627old
 */
rfUint32 rf627_protocol_old_get_size_of_request_hello_packet();
/**
 * @brief rf627_protocol_old_get_size_of_response_profile_header_packet
 * @return Size of response profile header in packet from rf627old
 */
rfUint32 rf627_protocol_old_get_size_of_response_profile_header_packet();
/**
 * @brief rf627_protocol_old_get_size_of_response_read_user_params_packet
 * @return Size of response profile header in packet from rf627old
 */
rfUint32 rf627_protocol_old_get_size_of_response_read_user_params_packet();
/**
 * @brief rf627_protocol_old_get_size_of_response_read_user_params_packet
 * @return Size of response profile header in packet from rf627old
 */
rfUint32 rf627_protocol_old_get_size_of_response_read_factory_params_packet();
/**
 * @brief rf627_protocol_old_get_size_of_response_profile_header_packet
 * @return Size of response profile header in packet from rf627old
 */
rfUint32 rf627_protocol_old_get_size_of_request_write_user_params_payload_packet();
/**
 * @brief rf627_protocol_old_get_size_of_response_profile_header_packet
 * @return Size of response profile header in packet from rf627old
 */
rfUint32 rf627_protocol_old_get_size_of_request_write_user_sensor_params_payload_packet();
/**
 * @brief rf627_protocol_old_get_size_of_response_write_user_params_packet
 * @return Size of response profile header in packet from rf627old
 */
rfUint32 rf627_protocol_old_get_size_of_response_write_user_params_packet();
/**
 * @brief rf627_protocol_old_get_size_of_response_save_user_params_packet
 * @return Size of response profile header in packet from rf627old
 */
rfUint32 rf627_protocol_old_get_size_of_response_save_user_params_packet();



//
// rf627_protocol_create
//

/**
 * @brief rf627_protocol_create_old_hello_msg - create hello msg for rf627old
 * @param reserved_1 - bit 0 (is the reserve)
 * @param checksum - Bit 1 (a sign of the presence of a checksum in the message)
 * @param is_last - Bit 2 (is a sign of the last command or response)
 * @param confirmation - Bit 3 (request for confirmation of response or command)
 * @param msg_type - Bits 7-4 (Message type)
 * @param msg_options - Not used yet
 * @param data_checksum - Data Area Checksum
 * @param reserved_2 - Not used yet
 * @param serial_number - Unique identifier of the device
 * @param msg_count - The msg counter (for confirmation)
 * @param cmd - Command ID - specific device command
 * @param payload_size - Payload data size
 * @return rf627_old_service_msg_t
 */
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
        );

/**
 * @brief rf627_protocol_create_old_request_hello_msg
 * @return old request hello msg
 */
rf627_old_header_msg_t rf627_protocol_old_create_hello_msg_request();

/**
 * @brief rf627_protocol_old_create_read_params_msg_request
 * @return old request read_params msg
 */
rf627_old_header_msg_t rf627_protocol_old_create_read_user_params_msg_request(
        rf627_protocol_old_header_confirmation_t confirmation,
        rfUint32                                 serial_number,
        rfUint16                                 msg_count
        );

/**
 * @brief rf627_protocol_old_create_read_params_msg_request
 * @return old request read_params msg
 */
rf627_old_header_msg_t rf627_protocol_old_create_read_factory_params_msg_request(
        rf627_protocol_old_header_confirmation_t confirmation,
        rfUint32                                 serial_number,
        rfUint16                                 msg_count
        );

/**
 * @brief rf627_protocol_old_create_write_user_params_msg_request
 * @return old request write_params msg
 */
rf627_old_header_msg_t rf627_protocol_old_create_write_user_params_msg_request(
        rf627_protocol_old_header_confirmation_t confirmation,
        rfUint32                                 serial_number,
        rfUint16                                 msg_count
        );

/**
 * @brief rf627_protocol_old_create_save_user_params_msg_request
 * @return old request write_params msg
 */
rf627_old_header_msg_t rf627_protocol_old_create_save_user_params_msg_request(
        rf627_protocol_old_header_confirmation_t confirmation,
        rfUint32                                 serial_number,
        rfUint16                                 msg_count
        );

/**
 * @brief rf627_protocol_old_create_write_user_params_msg_request
 * @return old request write_params msg
 */
rf627_old_header_msg_t rf627_protocol_old_create_write_user_sensor_params_msg_request(
        rf627_protocol_old_header_confirmation_t confirmation,
        rfUint32                                 serial_number,
        rfUint16                                 msg_count
        );


/**
 * @brief rf627_protocol_old_create_confirm_packet_from_response_packet
 * @param destination_buffer - Pointer to the request packet
 * @param destination_buffer_size - size of dest buffer
 * @param source_buffer - Pointer to the source response packet
 * @param source_buffer_size - size of source buffer
 * @return if confirmation is required - size of packet, else - 0
 */
rfSize rf627_protocol_old_create_confirm_packet_from_response_packet(
        rfUint8* destination_buffer, rfUint32 destination_buffer_size,
        rfUint8* source_buffer, rfUint32 source_buffer_size);

/**
 * @brief rf627_protocol_old_create_confirm_packet_from_response_profile_packet
 * @param destination_buffer - Pointer to the request packet
 * @param destination_buffer_size - size of dest buffer
 * @param source_buffer - Pointer to the source response packet
 * @param source_buffer_size - size of source buffer
 * @return if confirmation is required - size of packet, else - 0
 */
rfSize rf627_protocol_old_create_confirm_packet_from_response_profile_packet(
        rfUint8* destination_buffer, rfUint32 destination_buffer_size,
        rfUint8* source_buffer, rfUint32 source_buffer_size);

/**
 * @brief rf627_protocol_old_create_reset_counters_command_msg
 * @param confirmation
 * @param serial_number
 * @param msg_count
 * @param profile_counter
 * @param packet_counter
 * @return
 */
rf627_old_header_msg_t rf627_protocol_old_create_command_set_counters_msg(
        rf627_protocol_old_header_confirmation_t confirmation,
        rfUint32 serial_number,
        rfUint16 msg_count,
        rfUint32 profile_counter,
        rfUint32 packet_counter);

/**
 * @brief rf627_protocol_old_create_reset_counters_command_msg
 * @param confirmation
 * @param serial_number
 * @param msg_count
 * @param profile_counter
 * @param packet_counter
 * @return
 */
rf627_old_header_msg_t rf627_protocol_old_create_command_periphery_send_msg(
        rf627_protocol_old_header_confirmation_t confirmation,
        rfUint32 serial_number,
        rfUint16 msg_count,
        rfUint16 input_size);



//
// rf627_protocol_pack
//

/**
 * @brief rf627_protocol_pack_old_hello_msg_to_packet - pack hello msg to
 *        network packet
 * @param buffer - ptr to network buffer
 * @param msg - ptr to hello msg for rf627old
 * @return if successful - size of data packet, else - zero
 */
rfUint32 rf627_protocol_old_pack_header_msg_to_packet(
        rfUint8* buffer,
        rf627_old_header_msg_t* msg);
/**
 * @brief rf627_protocol_pack_old_request_hello_msg_to_packet
 * @param buffer - Pointer to the sending buffer.
 * @param buffer_size - buffer size
 * @param hello_msg - ptr to request hello msg for pack to sending buffer
 * @return if successful - Length in bytes of the encoded message, else - zero.
 */
rfSize rf627_protocol_old_pack_hello_msg_request_to_packet(
        rfUint8* buffer, rfUint32 buffer_size, rf627_old_header_msg_t* hello_msg);

/**
 * @brief rf627_protocol_old_create_read_params_msg_request
 * @return old request read_params msg
 */
rfSize rf627_protocol_old_pack_read_user_params_msg_request_to_packet(
        rfUint8* buffer, rfUint32 buffer_size, rf627_old_header_msg_t* msg);

/**
 * @brief rf627_protocol_old_create_read_params_msg_request
 * @return old request read_params msg
 */
rfSize rf627_protocol_old_pack_read_factory_params_msg_request_to_packet(
        rfUint8* buffer, rfUint32 buffer_size, rf627_old_header_msg_t* msg);

/**
 * @brief rf627_protocol_old_pack_write_user_params_msg_request_to_packet
 * @return old request read_params msg
 */
rfSize rf627_protocol_old_pack_write_user_params_msg_request_to_packet(
        rfUint8* buffer, rfUint32 buffer_size, rf627_old_header_msg_t* msg);

/**
 * @brief rf627_protocol_old_pack_write_user_params_msg_request_to_packet
 * @return old request read_params msg
 */
rfSize rf627_protocol_old_pack_save_user_params_msg_request_to_packet(
        rfUint8* buffer, rfUint32 buffer_size, rf627_old_header_msg_t* msg);


/**
 * @brief rf627_protocol_old_pack_command_set_counters_to_packet
 * @param buffer
 * @param buffer_size
 * @param msg
 * @return
 */
rfSize rf627_protocol_old_pack_command_set_counters_to_packet(
        rfUint8* buffer, rfUint32 buffer_size, rf627_old_header_msg_t* msg);

/**
 * @brief rf627_protocol_old_unpack_header_msg_from_profile_packet - unpack
 * payload msg from user_params network packet
 * @param buffer - ptr to network buffer
 * @return rf627_old_user_params_t
 */
rfUint32 rf627_protocol_old_pack_payload_msg_to_command_set_counter_packet(
        rfUint8* buffer, rfUint32 profile_counter, rfUint32 packet_counter);

/**
 * @brief rf627_protocol_old_unpack_header_msg_from_profile_packet - unpack
 * payload msg from user_params network packet
 * @param buffer - ptr to network buffer
 * @return rf627_old_user_params_t
 */
rfUint32 rf627_protocol_old_pack_payload_msg_to_command_periphery_send_packet(
        rfUint8* buffer, rfUint16 input_size, void* payload);


//
// rf627_protocol_unpack
//
/**
 * @brief rf627_protocol_unpack_old_hello_msg_from_packet - unpack hello msg from
 *        network packet
 * @param buffer - ptr to network buffer
 * @return rf627_old_service_msg_t
 */
rf627_old_header_msg_t rf627_protocol_old_unpack_header_msg_from_packet(
        rfUint8* buffer);
/**
 * @brief rf627_protocol_unpack_old_hello_header_from_packet
 * @param buffer
 * @return
 */
rf627_old_header_msg_t rf627_protocol_old_unpack_header_msg_from_hello_packet(
        rfUint8* buffer);

/**
 * @brief rf627_protocol_unpack_old_hello_msg_from_packet - unpack hello msg
 *        from network packet
 * @param buffer - ptr to network buffer
 * @return rf627_old_service_msg_t
 */
rf627_old_device_info_t rf627_protocol_old_unpack_payload_msg_from_hello_packet(
        rfUint8* buffer);
/**
 * @brief rf627_protocol_old_unpack_header_msg_from_profile_packet - unpack
 * profile header msg from network packet
 * @param buffer - ptr to network buffer
 * @return rf627_old_stream_msg_t
 */
rf627_old_stream_msg_t rf627_protocol_old_unpack_header_msg_from_profile_packet(
        rfUint8* buffer);

/**
 * @brief rf627_protocol_old_unpack_header_msg_from_profile_packet - unpack
 * user_params header msg from network packet
 * @param buffer - ptr to network buffer
 * @return rf627_old_header_msg_t
 */
rf627_old_header_msg_t rf627_protocol_old_unpack_header_msg_from_user_params_packet(
        rfUint8* buffer);

/**
 * @brief rf627_protocol_old_unpack_header_msg_from_profile_packet - unpack
 * user_params header msg from network packet
 * @param buffer - ptr to network buffer
 * @return rf627_old_header_msg_t
 */
rf627_old_header_msg_t rf627_protocol_old_unpack_header_msg_from_factory_params_packet(
        rfUint8* buffer);

/**
 * @brief rf627_protocol_old_unpack_header_msg_from_profile_packet - unpack
 * payload msg from user_params network packet
 * @param buffer - ptr to network buffer
 * @return rf627_old_user_params_t
 */
rf627_old_user_params_msg_t rf627_protocol_old_unpack_payload_msg_from_user_params_packet(
        rfUint8* buffer);

/**
 * @brief rf627_protocol_old_unpack_header_msg_from_profile_packet - unpack
 * payload msg from user_params network packet
 * @param buffer - ptr to network buffer
 * @return rf627_old_user_params_t
 */
rf627_old_factory_params_msg_t rf627_protocol_old_unpack_payload_msg_from_factory_params_packet(
        rfUint8* buffer);



rfBool rf627_protocol_send_packet_by_udp(
        void* s, rfUint8* msg, rfUint32 size,
        rfUint32 ip_addr, rfUint16 port,
        rfUint32 payload_length, void* payload);



rfUint32 srvc_proto_627_old_get_user_params_packet(
        rfUint8* buffer, rfUint32 size,
        rfUint32 serial_number, rfUint16 m_msg_count);

rfUint32 srvc_proto_627_old_get_answer_packet(
        rfUint8* recv, rfUint32 recv_size,
        rfUint8* answer_buffer, rfUint32 buffer_size);

rfUint32 srvc_proto_627_old_get_serial_number_from_message(
        rfUint8* message, rfUint32 message_size);

rfUint32 srvc_proto_627_old_get_counter_from_message(
        rfUint8* message, rfUint32 message_size);

rfUint32 srvc_proto_627_old_get_payload_from_message(
        rfUint8* message, rfUint32 message_size,
        rfUint8* buffer, rfUint32 buffer_size);


#endif // RF627_PROTOCOL
