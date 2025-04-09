#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <efivar/efivar.h>
#include <wchar.h>
#include <locale.h>
#include <stdint.h> // For explicit integer types

// GUID for EFI Global Variable
static efi_guid_t global = EFI_GLOBAL_GUID;

// Boot Option Attributes
#define LOAD_OPTION_ACTIVE 0x00000001
#define LOAD_OPTION_FORCE_RECONNECT 0x00000002

// --- Device Path Types and Subtypes (unchanged) ---
// EFI Device Path Types
#define HARDWARE_DEVICE_PATH 0x01
#define ACPI_DEVICE_PATH 0x02
#define MESSAGING_DEVICE_PATH 0x03
#define MEDIA_DEVICE_PATH 0x04
#define BBS_DEVICE_PATH 0x05
#define END_DEVICE_PATH_TYPE 0x7F
#define END_ENTIRE_DEVICE_PATH_SUBTYPE 0xFF

// Media Device Path Subtypes
#define MEDIA_HARDDRIVE_DP 0x01
#define MEDIA_CDROM_DP 0x02
#define MEDIA_VENDOR_DP 0x03
#define MEDIA_FILEPATH_DP 0x04
#define MEDIA_PROTOCOL_DP 0x05

// Messaging Device Path Subtypes
#define MSG_ATAPI_DP 0x01
#define MSG_SCSI_DP 0x02
#define MSG_FIBRE_CHANNEL_DP 0x03
#define MSG_1394_DP 0x04
#define MSG_USB_DP 0x05
#define MSG_I2O_DP 0x06
#define MSG_INFINIBAND_DP 0x09
#define MSG_VENDOR_DP 0x0A
#define MSG_MAC_ADDR_DP 0x0B
#define MSG_IPv4_DP 0x0C
#define MSG_IPv6_DP 0x0D
#define MSG_UART_DP 0x0E
#define MSG_USB_CLASS_DP 0x0F
#define MSG_USB_WWID_DP 0x10
#define MSG_DEVICE_LOGICAL_UNIT_DP 0x11
#define MSG_SATA_DP 0x12
#define MSG_ISCSI_DP 0x13
#define MSG_VLAN_DP 0x14
#define MSG_FIBRE_CHANNEL_EX_DP 0x15
#define MSG_SAS_EX_DP 0x16
#define MSG_NVME_NAMESPACE_DP 0x17
#define MSG_URI_DP 0x18
#define MSG_UFS_DP 0x19
#define MSG_SD_DP 0x1A
#define MSG_BLUETOOTH_DP 0x1B
#define MSG_WIFI_DP 0x1C
#define MSG_EMMC_DP 0x1D
#define MSG_BLUETOOTH_LE_DP 0x1E
#define MSG_DNS_DP 0x1F
// --- End Device Path Types and Subtypes ---

// --- utf16le_to_utf8 function (unchanged, with note about static buffer) ---
// WARNING: Uses a static buffer. Not thread-safe and limited length.
char *utf16le_to_utf8(const uint16_t *utf16_str, size_t max_len_bytes)
{
    static char utf8_buf[1024];            // Static buffer!
    memset(utf8_buf, 0, sizeof(utf8_buf)); // Clear buffer
    size_t i_bytes = 0, j = 0;

    while (i_bytes + sizeof(uint16_t) <= max_len_bytes && j < sizeof(utf8_buf) - 4)
    {
        uint16_t c;
        memcpy(&c, (const uint8_t *)utf16_str + i_bytes, sizeof(uint16_t));
        i_bytes += sizeof(uint16_t);

        if (c == 0)
            break; // Null-Terminator found

        if (c < 0x80)
        {
            utf8_buf[j++] = (char)c;
        }
        else if (c < 0x800)
        {
            if (j + 1 >= sizeof(utf8_buf) - 1)
                break;
            utf8_buf[j++] = 0xC0 | (c >> 6);
            utf8_buf[j++] = 0x80 | (c & 0x3F);
        }
        else if (c >= 0xD800 && c <= 0xDBFF)
        { // High Surrogate
            if (i_bytes + sizeof(uint16_t) <= max_len_bytes)
            {
                uint16_t c2;
                memcpy(&c2, (const uint8_t *)utf16_str + i_bytes, sizeof(uint16_t));
                if (c2 >= 0xDC00 && c2 <= 0xDFFF)
                { // Low Surrogate
                    if (j + 3 >= sizeof(utf8_buf) - 1)
                        break;
                    uint32_t code_point = 0x10000 + (((c & 0x3FF) << 10) | (c2 & 0x3FF));
                    utf8_buf[j++] = 0xF0 | (code_point >> 18);
                    utf8_buf[j++] = 0x80 | ((code_point >> 12) & 0x3F);
                    utf8_buf[j++] = 0x80 | ((code_point >> 6) & 0x3F);
                    utf8_buf[j++] = 0x80 | (code_point & 0x3F);
                    i_bytes += sizeof(uint16_t); // Consumed additional character
                }
                else
                { // High surrogate without Low surrogate -> Error
                    if (j >= sizeof(utf8_buf) - 1)
                        break;
                    utf8_buf[j++] = '?';
                }
            }
            else
            { // End of data after High Surrogate
                if (j >= sizeof(utf8_buf) - 1)
                    break;
                utf8_buf[j++] = '?';
                break;
            }
        }
        else if (c >= 0xDC00 && c <= 0xDFFF)
        { // Low surrogate without High surrogate -> Error
            if (j >= sizeof(utf8_buf) - 1)
                break;
            utf8_buf[j++] = '?';
        }
        else
        { // Normal 3-byte UTF-8 character
            if (j + 2 >= sizeof(utf8_buf) - 1)
                break;
            utf8_buf[j++] = 0xE0 | (c >> 12);
            utf8_buf[j++] = 0x80 | ((c >> 6) & 0x3F);
            utf8_buf[j++] = 0x80 | (c & 0x3F);
        }
    }
    utf8_buf[j] = '\0'; // Ensure the string is null-terminated
    return utf8_buf;
}
// --- End utf16le_to_utf8 function ---

// Structure for the header of a Device Path node
typedef struct __attribute__((packed))
{
    uint8_t Type;
    uint8_t SubType;
    uint16_t Length;
} EFI_DEVICE_PATH_PROTOCOL_HEADER;

// Debug output of raw data
void debug_print_raw_data(const uint8_t *data, size_t size)
{
    printf("\nRaw Device Path Data (Size: %zu Bytes):\n", size);
    for (size_t i = 0; i < size; i++)
    {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    if (size % 16 != 0)
        printf("\n"); // Line break at the end if needed
}

// CORRECTED function for printing the Device Path (heuristics removed)
void print_device_path(const uint8_t *path_data, size_t path_size)
{
    printf("Device path: ");
    if (path_data == NULL || path_size < sizeof(EFI_DEVICE_PATH_PROTOCOL_HEADER))
    {
        printf("(Invalid or empty)\n");
        return;
    }

    // Debug output of raw data
    debug_print_raw_data(path_data, path_size);

    size_t offset = 0;
    int first_node = 1;
    int error_count = 0;
    const int MAX_ERRORS = 3;

    printf("  Parsed: "); // Label for parsed output

    while (offset < path_size && error_count < MAX_ERRORS)
    {
        // Read header of current node
        if (offset + sizeof(EFI_DEVICE_PATH_PROTOCOL_HEADER) > path_size)
        {
            fprintf(stderr, "\n  Error: Unexpected end of Device Path while reading header (Offset %zu).\n", offset);
            break;
        }

        EFI_DEVICE_PATH_PROTOCOL_HEADER header;
        // Ensure enough data is available for the header
        memcpy(&header, path_data + offset, sizeof(EFI_DEVICE_PATH_PROTOCOL_HEADER));

        // Check node length (must be at least header size)
        if (header.Length < sizeof(EFI_DEVICE_PATH_PROTOCOL_HEADER))
        {
            fprintf(stderr, "\n  Error: Invalid length (%u < %zu) in Device Path node at offset %zu.\n",
                    header.Length, sizeof(EFI_DEVICE_PATH_PROTOCOL_HEADER), offset);
            error_count++;
            // Break on invalid length as continuing is unsafe
            break;
        }

        // Check if node extends beyond end of data
        if (offset + header.Length > path_size)
        {
            fprintf(stderr, "\n  Error: Node length (%u) exceeds total size (%zu) of Device Path at offset %zu.\n",
                    header.Length, path_size, offset);
            error_count++;
            // Break on invalid length
            break;
        }

        // Check for end node (can be anywhere but must be at the end)
        if (header.Type == END_DEVICE_PATH_TYPE)
        {
            if (header.SubType == END_ENTIRE_DEVICE_PATH_SUBTYPE)
            {
                // Correct end node for entire path
                if (!first_node)
                    printf("/"); // Separator if not first node
                printf("End(Entire)");
                offset += header.Length; // Jump to end
                break;                   // Normal end of parsing
            }
            else
            {
                // Other end node subtype (e.g. End of Instance)
                if (!first_node)
                    printf("/");
                printf("End(Instance)"); // Or more specific based on SubType
                offset += header.Length;
            }
        }
        else // Regular node
        {
            // Add separator between nodes (except before first)
            if (!first_node)
            {
                printf("/");
            }
            first_node = 0;

            // Interpret node based on type and subtype
            switch (header.Type)
            {
            case MEDIA_DEVICE_PATH:
                switch (header.SubType)
                {
                case MEDIA_FILEPATH_DP:
                {
                    // Data starts after header
                    const uint8_t *filepath_data = path_data + offset + sizeof(EFI_DEVICE_PATH_PROTOCOL_HEADER);
                    // Payload length = total node length - header length
                    size_t filepath_bytes = header.Length - sizeof(EFI_DEVICE_PATH_PROTOCOL_HEADER);

                    // Note: utf16le_to_utf8 expects max_len_bytes, not character count
                    printf("%s", utf16le_to_utf8((const uint16_t *)filepath_data, filepath_bytes));
                    break;
                }
                case MEDIA_HARDDRIVE_DP:
                    printf("HD(...)");
                    break;
                case MEDIA_CDROM_DP:
                    printf("CDROM(...)");
                    break;
                case MEDIA_VENDOR_DP:
                    printf("MediaVendor(...)");
                    break;
                case MEDIA_PROTOCOL_DP:
                    printf("MediaProto(...)");
                    break;
                default:
                    printf("Media(SubType=0x%02x)", header.SubType);
                    break;
                }
                break;

            case HARDWARE_DEVICE_PATH:
                printf("Hw(SubType=0x%02x)", header.SubType);
                break;

            case ACPI_DEVICE_PATH:
                if (header.SubType == 0x01)
                    printf("Acpi(PNP...)");
                else if (header.SubType == 0x02)
                    printf("Acpi(HID...)");
                else
                    printf("Acpi(SubType=0x%02x)", header.SubType);
                break;

            case MESSAGING_DEVICE_PATH:
                if (header.SubType == MSG_USB_DP)
                    printf("Usb(Port?,Interface?)");
                else if (header.SubType == MSG_SATA_DP)
                    printf("Sata(Port,Multiplier,Lun)");
                else if (header.SubType == MSG_NVME_NAMESPACE_DP)
                    printf("Nvme(NSID,UUID)");
                else if (header.SubType == MSG_MAC_ADDR_DP)
                    printf("MAC(...)");
                else if (header.SubType == MSG_IPv4_DP)
                    printf("IPv4(...)");
                else if (header.SubType == MSG_IPv6_DP)
                    printf("IPv6(...)");
                else if (header.SubType == MSG_URI_DP)
                    printf("Uri(...)");
                else
                    printf("Msg(SubType=0x%02x)", header.SubType);
                break;

            case BBS_DEVICE_PATH:
                printf("BBS(Type=0x%02x)", header.SubType);
                break;

            default:
                printf("Unknown(Type=0x%02x, SubType=0x%02x)", header.Type, header.SubType);
                break;
            }
            offset += header.Length;
        }
    }

    if (offset < path_size)
    {
        EFI_DEVICE_PATH_PROTOCOL_HEADER final_header;
        if (offset + sizeof(final_header) <= path_size)
        {
            memcpy(&final_header, path_data + offset, sizeof(final_header));
            if (final_header.Type != END_DEVICE_PATH_TYPE || final_header.SubType != END_ENTIRE_DEVICE_PATH_SUBTYPE)
            {
                printf("\n  Warning: Parsing ended at offset %zu, but no complete end node found. Remaining bytes: %zu.", offset, path_size - offset);
            }
        }
        else
        {
            printf("\n  Warning: Parsing ended at offset %zu, but not enough data for end node. Remaining bytes: %zu.", offset, path_size - offset);
        }
    }
    else if (offset > path_size)
    {
        printf("\n  Error: Offset (%zu) exceeded total size (%zu).", offset, path_size);
    }

    if (error_count >= MAX_ERRORS)
    {
        printf("\n  Warning: Too many errors while parsing Device Path. Aborting.\n");
    }
    else
    {
        printf("\n");
    }
}

// Hex-Dump function
void print_hex_dump(const char *label, const uint8_t *data, size_t size)
{
    if (size == 0)
        return;
    printf("%s (%zu Bytes):", label, size);
    for (size_t i = 0; i < size; i++)
    {
        if (i % 16 == 0)
            printf("\n  ");
        printf("%02x ", data[i]);
    }
    if (size > 32 && size % 16 != 0)
        printf("\n  ...");
    else if (size % 16 != 0 || size == 0)
        printf("\n");
    else
        printf("\n");
}

int main(void)
{
    setlocale(LC_ALL, "");

    if (efi_variables_supported() != 1)
    {
        fprintf(stderr, "EFI variables are not supported.\n");
        return EXIT_FAILURE;
    }

    printf("EFI Boot Entries:\n");

    uint8_t *boot_order_data = NULL;
    size_t boot_order_size = 0;
    uint32_t boot_order_attributes = 0;

    int rc = efi_get_variable(EFI_GLOBAL_GUID, "BootOrder",
                              &boot_order_data, &boot_order_size, &boot_order_attributes);
    if (rc < 0)
    {
        fprintf(stderr, "Error reading boot order: %s (errno %d)\n", strerror(errno), errno);
        return EXIT_FAILURE;
    }

    if (boot_order_size == 0 || boot_order_size % sizeof(uint16_t) != 0)
    {
        fprintf(stderr, "Error: Invalid size (%zu bytes) for BootOrder variable.\n", boot_order_size);
        free(boot_order_data);
        return EXIT_FAILURE;
    }
    uint16_t *boot_order = (uint16_t *)boot_order_data;
    size_t num_entries = boot_order_size / sizeof(uint16_t);

    printf("\nBoot Order: ");
    for (size_t i = 0; i < num_entries; i++)
    {
        printf("%04X%s", boot_order[i], (i < num_entries - 1) ? ", " : "\n");
    }

    for (size_t i = 0; i < num_entries; i++)
    {
        char boot_var_name[9];
        snprintf(boot_var_name, sizeof(boot_var_name), "Boot%04X", boot_order[i]);

        uint8_t *entry_data = NULL;
        size_t entry_data_size = 0;
        uint32_t entry_attributes_var = 0;

        rc = efi_get_variable(EFI_GLOBAL_GUID, boot_var_name,
                              &entry_data, &entry_data_size, &entry_attributes_var);
        if (rc < 0)
        {
            fprintf(stderr, "\nError reading %s: %s (errno %d)\n",
                    boot_var_name, strerror(errno), errno);
            continue;
        }

        printf("\n=== Boot Entry: %s ===\n", boot_var_name);

        if (entry_data_size < sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t))
        {
            fprintf(stderr, "  Error: Entry %s is too small (%zu bytes).\n", boot_var_name, entry_data_size);
            free(entry_data);
            continue;
        }

        uint32_t entry_load_attributes;
        memcpy(&entry_load_attributes, entry_data, sizeof(uint32_t));
        printf("Status: %s\n", (entry_load_attributes & LOAD_OPTION_ACTIVE) ? "Active" : "Inactive");
        if (entry_load_attributes & LOAD_OPTION_FORCE_RECONNECT)
            printf("        Force Reconnect enabled\n");

        uint16_t file_path_list_length;
        memcpy(&file_path_list_length, entry_data + sizeof(uint32_t), sizeof(uint16_t));

        const uint16_t *description_start = (const uint16_t *)(entry_data + sizeof(uint32_t) + sizeof(uint16_t));
        size_t current_offset = sizeof(uint32_t) + sizeof(uint16_t);
        size_t desc_max_bytes = entry_data_size - current_offset;
        size_t desc_len_chars = 0;
        while (current_offset + (desc_len_chars + 1) * sizeof(uint16_t) <= entry_data_size)
        {
            if (description_start[desc_len_chars] == 0)
            {
                break;
            }
            if (current_offset + (desc_len_chars + 1) * sizeof(uint16_t) + file_path_list_length > entry_data_size)
            {
                fprintf(stderr, "  Warning: Inconsistent length specifications for %s. Description appears too long.\n", boot_var_name);
                desc_len_chars = 0;
                break;
            }
            desc_len_chars++;
            if (desc_len_chars * sizeof(uint16_t) > desc_max_bytes)
            {
                fprintf(stderr, "  Error: Description in %s appears not properly null-terminated or is too long.\n", boot_var_name);
                desc_len_chars = 0;
                break;
            }
        }
        size_t desc_len_bytes = (desc_len_chars + 1) * sizeof(uint16_t);

        printf("Name: %s\n", utf16le_to_utf8(description_start, desc_len_chars * sizeof(uint16_t)));

        uint8_t *device_path_start = entry_data + sizeof(uint32_t) + sizeof(uint16_t) + desc_len_bytes;
        size_t device_path_offset = sizeof(uint32_t) + sizeof(uint16_t) + desc_len_bytes;

        if (device_path_offset + file_path_list_length > entry_data_size)
        {
            fprintf(stderr, "  Error: Calculated device path start (%zu) + length (%u) exceeds total size (%zu) for %s.\n",
                    device_path_offset, file_path_list_length, entry_data_size, boot_var_name);
            if (entry_data_size > device_path_offset)
            {
                file_path_list_length = entry_data_size - device_path_offset;
                fprintf(stderr, "  Attempting to continue with corrected path length %u.\n", file_path_list_length);
            }
            else
            {
                fprintf(stderr, "  No data left for device path.\n");
                file_path_list_length = 0;
            }
        }

        if (file_path_list_length > 0)
        {
            print_device_path(device_path_start, file_path_list_length);
        }
        else
        {
            printf("Device path: (Empty or error in length calculation)\n");
        }

        size_t optional_data_offset = device_path_offset + file_path_list_length;
        if (optional_data_offset < entry_data_size)
        {
            size_t optional_data_size = entry_data_size - optional_data_offset;
            uint8_t *optional_data_start = entry_data + optional_data_offset;
            print_hex_dump("Additional Data", optional_data_start, optional_data_size);
        }
        else if (optional_data_offset > entry_data_size)
        {
            fprintf(stderr, "  Warning: Inconsistency in optional data calculation for %s (Offset %zu > Size %zu).\n",
                    boot_var_name, optional_data_offset, entry_data_size);
        }

        free(entry_data);
    }

    free(boot_order_data);
    return EXIT_SUCCESS;
}