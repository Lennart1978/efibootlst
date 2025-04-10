#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <efivar/efivar.h>
#include <wchar.h>
#include <locale.h>
#include <stdint.h>   // For explicit integer types
#include <inttypes.h> // For PRIu64 used in NVMe printing
#include <stddef.h>   // For offsetof

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

// --- Base Device Path Structure Header ---
// MUST be defined before structures that use it.
typedef struct __attribute__((packed))
{
    uint8_t Type;
    uint8_t SubType;
    uint16_t Length;
} EFI_DEVICE_PATH_PROTOCOL_HEADER;

// --- Device Path Structures ---
// Refer to UEFI Specification 2.10, Section 10.3 Device Path Nodes.

typedef struct __attribute__((packed))
{
    EFI_DEVICE_PATH_PROTOCOL_HEADER Header;
    uint32_t PartitionNumber;
    uint64_t PartitionStart;
    uint64_t PartitionSize;
    uint8_t Signature[16]; // GUID or MBR Signature
    uint8_t MBRType;       // Partition Format (GPT/MBR)
    uint8_t SignatureType; // Signature Type (GUID/MBR)
} HARD_DRIVE_DEVICE_PATH;

#define MBR_TYPE_PCAT 0x01
#define MBR_TYPE_EFI_PARTITION_TABLE_HEADER 0x02

#define SIGNATURE_TYPE_MBR 0x01
#define SIGNATURE_TYPE_GUID 0x02

typedef struct __attribute__((packed))
{
    EFI_DEVICE_PATH_PROTOCOL_HEADER Header;
    uint16_t HBAPortNumber;
    uint16_t PortMultiplierPortNumber;
    uint16_t Lun; // Logical Unit Number
} SATA_DEVICE_PATH;

typedef struct __attribute__((packed))
{
    EFI_DEVICE_PATH_PROTOCOL_HEADER Header;
    uint32_t NamespaceId;
    uint64_t NamespaceUuid; // Actually IEEE EUI-64 identifier, not UUID
} NVME_NAMESPACE_DEVICE_PATH;

typedef struct __attribute__((packed))
{
    EFI_DEVICE_PATH_PROTOCOL_HEADER Header;
    uint8_t ParentPortNumber;
    uint8_t InterfaceNumber;
} USB_DEVICE_PATH;

// Used for both ACPI_DEVICE_PATH Subtype 0x01 (PNP) and 0x02 (HID)
// For Subtype 0x01, CID is assumed 0 or ignored.
// For Subtype 0x02, UID might be optional based on length.
typedef struct __attribute__((packed))
{
    EFI_DEVICE_PATH_PROTOCOL_HEADER Header;
    uint32_t HID;       // Hardware ID (EISA ID Format for PNP) or HID
    uint32_t UID;       // Unique ID (if present, usually 0 for PNP)
    uint32_t CID;       // Compatible ID (for HID, if present)
} ACPI_HID_DEVICE_PATH; // Naming reflects the structure containing HID/UID/CID

// --- End Device Path Structures ---

// --- utf16le_to_utf8 function ---
// Converts a UTF-16LE string to a dynamically allocated UTF-8 string.
// Returns NULL on error (e.g., allocation failure).
// The caller is responsible for freeing the returned string.
char *utf16le_to_utf8(const uint16_t *utf16_str, size_t max_len_bytes)
{
    // Estimate initial buffer size (can be refined)
    // Worst case: 4 bytes UTF-8 per UTF-16 char + null terminator
    size_t initial_buf_size = (max_len_bytes / sizeof(uint16_t)) * 4 + 1;
    if (initial_buf_size < 128)
        initial_buf_size = 128; // Minimum size

    char *utf8_buf = malloc(initial_buf_size);
    if (!utf8_buf)
    {
        perror("Failed to allocate memory for UTF-8 conversion");
        return NULL;
    }
    size_t buf_size = initial_buf_size;
    // No need to memset to 0 if we correctly null-terminate at the end

    size_t i_bytes = 0; // Input byte index
    size_t j = 0;       // Output byte index (UTF-8 buffer)

    while (i_bytes + sizeof(uint16_t) <= max_len_bytes)
    {
        // Check if buffer needs resizing (leave space for worst-case: 4 bytes + null)
        if (j + 5 >= buf_size)
        {
            size_t new_size = buf_size * 2;
            // Prevent potential integer overflow for very large strings
            if (new_size < buf_size)
            {
                fprintf(stderr, "Error: Buffer size overflow during UTF-8 conversion.\n");
                free(utf8_buf);
                return NULL;
            }
            char *new_buf = realloc(utf8_buf, new_size);
            if (!new_buf)
            {
                perror("Failed to reallocate memory for UTF-8 conversion");
                free(utf8_buf);
                return NULL;
            }
            utf8_buf = new_buf;
            buf_size = new_size;
            // Note: The newly allocated part is not zeroed by realloc
        }

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
            // Need 2 bytes
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
                    // Need 4 bytes
                    uint32_t code_point = 0x10000 + (((c & 0x3FF) << 10) | (c2 & 0x3FF));
                    utf8_buf[j++] = 0xF0 | (code_point >> 18);
                    utf8_buf[j++] = 0x80 | ((code_point >> 12) & 0x3F);
                    utf8_buf[j++] = 0x80 | ((code_point >> 6) & 0x3F);
                    utf8_buf[j++] = 0x80 | (code_point & 0x3F);
                    i_bytes += sizeof(uint16_t); // Consumed additional character
                }
                else
                { // High surrogate without Low surrogate -> Error
                    utf8_buf[j++] = '?';
                }
            }
            else
            { // End of data after High Surrogate
                utf8_buf[j++] = '?';
                break;
            }
        }
        else if (c >= 0xDC00 && c <= 0xDFFF)
        { // Low surrogate without High surrogate -> Error
            utf8_buf[j++] = '?';
        }
        else
        { // Normal 3-byte UTF-8 character
            // Need 3 bytes
            utf8_buf[j++] = 0xE0 | (c >> 12);
            utf8_buf[j++] = 0x80 | ((c >> 6) & 0x3F);
            utf8_buf[j++] = 0x80 | (c & 0x3F);
        }
    }
    utf8_buf[j] = '\0'; // Ensure the string is null-terminated

    // Optional: Shrink buffer to actual size (trade-off: extra realloc vs memory saving)
    // Consider adding this if memory usage is critical
    /*
    char *final_buf = realloc(utf8_buf, j + 1);
    if (!final_buf) {
         // If shrinking fails, return the larger buffer, it's still valid
         perror("Warning: Failed to shrink buffer during UTF-8 conversion");
         return utf8_buf;
     }
    return final_buf;
    */

    return utf8_buf; // Return potentially oversized buffer
}
// --- End utf16le_to_utf8 function ---

// Helper function to print GUID from raw bytes
void print_guid_from_bytes(const uint8_t *guid_bytes)
{
    printf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
           guid_bytes[3], guid_bytes[2], guid_bytes[1], guid_bytes[0],                                      // Data1 (LE)
           guid_bytes[5], guid_bytes[4],                                                                    // Data2 (LE)
           guid_bytes[7], guid_bytes[6],                                                                    // Data3 (LE)
           guid_bytes[8], guid_bytes[9],                                                                    // Data4[0..1]
           guid_bytes[10], guid_bytes[11], guid_bytes[12], guid_bytes[13], guid_bytes[14], guid_bytes[15]); // Data4[2..7]
}

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

    printf("Parsed: "); // Label for parsed output

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

        const uint8_t *node_data_start = path_data + offset;
        const uint8_t *payload_start = node_data_start + sizeof(EFI_DEVICE_PATH_PROTOCOL_HEADER);
        size_t payload_size = header.Length - sizeof(EFI_DEVICE_PATH_PROTOCOL_HEADER);

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
                    // Data starts after header - payload_start already points here
                    // Payload length = payload_size
                    if (payload_size > 0)
                    {
                        // Note: utf16le_to_utf8 expects max_len_bytes, not character count
                        char *utf8_str = utf16le_to_utf8((const uint16_t *)payload_start, payload_size);
                        if (utf8_str)
                        {
                            printf("File(%s)", utf8_str); // Changed prefix for clarity
                            free(utf8_str);
                        }
                        else
                        {
                            printf("File(Error converting path)");
                        }
                    }
                    else
                    {
                        printf("File(Empty Path)");
                    }
                    break;
                }
                case MEDIA_HARDDRIVE_DP:
                    if (header.Length >= sizeof(HARD_DRIVE_DEVICE_PATH))
                    {
                        HARD_DRIVE_DEVICE_PATH hd_data;
                        memcpy(&hd_data, node_data_start, sizeof(HARD_DRIVE_DEVICE_PATH)); // Copy entire struct including header
                        printf("HD(Part=%u,SigType=%u,", hd_data.PartitionNumber, hd_data.SignatureType);
                        if (hd_data.SignatureType == SIGNATURE_TYPE_GUID)
                        {
                            printf("Sig=");
                            // Directly use the bytes from the structure
                            print_guid_from_bytes(hd_data.Signature);
                        }
                        else if (hd_data.SignatureType == SIGNATURE_TYPE_MBR)
                        {
                            printf("Sig=%02x%02x%02x%02x", hd_data.Signature[0], hd_data.Signature[1], hd_data.Signature[2], hd_data.Signature[3]);
                        }
                        else
                        {
                            printf("Sig=Unknown");
                        }
                        printf(",Format=%s)", hd_data.MBRType == MBR_TYPE_PCAT ? "MBR" : (hd_data.MBRType == MBR_TYPE_EFI_PARTITION_TABLE_HEADER ? "GPT" : "Unknown"));
                    }
                    else
                    {
                        printf("HD(Data too short)");
                    }
                    break;
                case MEDIA_CDROM_DP:
                    // Could parse BootEntry and other fields if needed
                    printf("CDROM(...)");
                    break;
                case MEDIA_VENDOR_DP:
                    // Vendor GUID would be in payload_start
                    printf("MediaVendor(...)");
                    break;
                case MEDIA_PROTOCOL_DP:
                    // Protocol GUID would be in payload_start
                    if (payload_size >= sizeof(efi_guid_t))
                    {
                        // We don't have efi_guid_t readily available here, print raw bytes
                        // efi_guid_t proto_guid;
                        // memcpy(&proto_guid, payload_start, sizeof(efi_guid_t));
                        printf("MediaProto(GUID=");
                        print_guid_from_bytes(payload_start);
                        printf(")");
                    }
                    else
                    {
                        printf("MediaProto(Invalid GUID size)");
                    }
                    break;
                default:
                    printf("Media(SubType=0x%02x)", header.SubType);
                    break;
                }
                break;

            case HARDWARE_DEVICE_PATH:
                // Example: PCI - would require PCI_DEVICE_PATH struct
                printf("Hw(SubType=0x%02x)", header.SubType);
                break;

            case ACPI_DEVICE_PATH:
                if (header.SubType == 0x01)
                { // ACPI_DEVICE_PATH_SUBTYPE
                    // Check if length allows reading HID and potentially UID
                    if (header.Length >= offsetof(ACPI_HID_DEVICE_PATH, UID) + sizeof(uint32_t))
                    {
                        ACPI_HID_DEVICE_PATH acpi_data;
                        memcpy(&acpi_data, node_data_start, offsetof(ACPI_HID_DEVICE_PATH, UID) + sizeof(uint32_t)); // Read HID and UID
                        // EISA ID conversion: (HI << 16) | LO -> "PNPxxxx" or "ABCxxxx"
                        char pnp[8];
                        uint32_t hid = acpi_data.HID;
                        sprintf(pnp, "%c%c%c%04X",
                                ((hid >> 10) & 0x1F) + 'A' - 1,
                                ((hid >> 5) & 0x1F) + 'A' - 1,
                                (hid & 0x1F) + 'A' - 1,
                                (hid >> 16) & 0xFFFF);
                        if (acpi_data.UID != 0)
                        {
                            printf("Acpi(PNP=%s,UID=%u)", pnp, acpi_data.UID);
                        }
                        else
                        {
                            printf("Acpi(PNP=%s)", pnp);
                        }
                    }
                    else if (header.Length >= offsetof(ACPI_HID_DEVICE_PATH, UID))
                    {
                        ACPI_HID_DEVICE_PATH acpi_data;
                        memcpy(&acpi_data, node_data_start, offsetof(ACPI_HID_DEVICE_PATH, UID)); // Read only HID
                        char pnp[8];
                        uint32_t hid = acpi_data.HID;
                        sprintf(pnp, "%c%c%c%04X",
                                ((hid >> 10) & 0x1F) + 'A' - 1,
                                ((hid >> 5) & 0x1F) + 'A' - 1,
                                (hid & 0x1F) + 'A' - 1,
                                (hid >> 16) & 0xFFFF);
                        printf("Acpi(PNP=%s)", pnp);
                    }
                    else
                    {
                        printf("Acpi(PNP Data too short)");
                    }
                }
                else if (header.SubType == 0x02)
                { // ACPI_EXTENDED_DP
                    // Check length for HID, UID, CID
                    if (header.Length >= sizeof(ACPI_HID_DEVICE_PATH))
                    {
                        ACPI_HID_DEVICE_PATH acpi_data;
                        memcpy(&acpi_data, node_data_start, sizeof(ACPI_HID_DEVICE_PATH));
                        // Format depends on HID type (PNP or other)
                        printf("AcpiEx(HID=0x%x,UID=%u,CID=0x%x)", acpi_data.HID, acpi_data.UID, acpi_data.CID);
                    }
                    else if (header.Length >= offsetof(ACPI_HID_DEVICE_PATH, CID))
                    {
                        ACPI_HID_DEVICE_PATH acpi_data;
                        memcpy(&acpi_data, node_data_start, offsetof(ACPI_HID_DEVICE_PATH, CID));
                        printf("AcpiEx(HID=0x%x,UID=%u)", acpi_data.HID, acpi_data.UID);
                    }
                    else if (header.Length >= offsetof(ACPI_HID_DEVICE_PATH, UID))
                    {
                        ACPI_HID_DEVICE_PATH acpi_data;
                        memcpy(&acpi_data, node_data_start, offsetof(ACPI_HID_DEVICE_PATH, UID));
                        printf("AcpiEx(HID=0x%x)", acpi_data.HID);
                    }
                    else
                    {
                        printf("AcpiEx(Data too short)");
                    }
                }
                else
                {
                    printf("Acpi(SubType=0x%02x)", header.SubType);
                }
                break;

            case MESSAGING_DEVICE_PATH:
                switch (header.SubType)
                {
                case MSG_USB_DP:
                    if (header.Length >= sizeof(USB_DEVICE_PATH))
                    {
                        USB_DEVICE_PATH usb_data;
                        memcpy(&usb_data, node_data_start, sizeof(USB_DEVICE_PATH));
                        printf("Usb(ParentPort=%u,If=%u)", usb_data.ParentPortNumber, usb_data.InterfaceNumber);
                    }
                    else
                    {
                        printf("Usb(Data too short)");
                    }
                    break;
                case MSG_SATA_DP:
                    if (header.Length >= sizeof(SATA_DEVICE_PATH))
                    {
                        SATA_DEVICE_PATH sata_data;
                        memcpy(&sata_data, node_data_start, sizeof(SATA_DEVICE_PATH));
                        printf("Sata(Port=%u,Multiplier=%u,Lun=%u)", sata_data.HBAPortNumber, sata_data.PortMultiplierPortNumber, sata_data.Lun);
                    }
                    else
                    {
                        printf("Sata(Data too short)");
                    }
                    break;
                case MSG_NVME_NAMESPACE_DP:
                    if (header.Length >= sizeof(NVME_NAMESPACE_DEVICE_PATH))
                    {
                        NVME_NAMESPACE_DEVICE_PATH nvme_data;
                        memcpy(&nvme_data, node_data_start, sizeof(NVME_NAMESPACE_DEVICE_PATH));
                        // Note: NamespaceUuid is EUI-64, print as hex for now
                        printf("Nvme(NSID=%u,EUI64=0x%016lx)", nvme_data.NamespaceId, nvme_data.NamespaceUuid);
                    }
                    else
                    {
                        printf("Nvme(Data too short)");
                    }
                    break;
                case MSG_MAC_ADDR_DP:
                    // MAC address is in payload_start (payload_size bytes)
                    printf("MAC(...)");
                    break;
                case MSG_IPv4_DP:
                    // IPv4 address details in payload
                    printf("IPv4(...)");
                    break;
                case MSG_IPv6_DP:
                    // IPv6 address details in payload
                    printf("IPv6(...)");
                    break;
                case MSG_URI_DP:
                    // URI string in payload (UTF-8)
                    if (payload_size > 0)
                    {
                        // Ensure null termination for safety, though UEFI spec says it's not null terminated
                        char *uri_str = malloc(payload_size + 1);
                        if (uri_str)
                        {
                            memcpy(uri_str, payload_start, payload_size);
                            uri_str[payload_size] = '\0';
                            printf("Uri(%s)", uri_str);
                            free(uri_str);
                        }
                        else
                        {
                            printf("Uri(Mem Alloc Error)");
                        }
                    }
                    else
                    {
                        printf("Uri(Empty)");
                    }
                    break;
                default:
                    printf("Msg(SubType=0x%02x)", header.SubType);
                    break;
                }
                break;

            case BBS_DEVICE_PATH:
                // BBS_DEVICE_PATH struct could be added to show DeviceType etc.
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

        // Call utf16le_to_utf8 and handle the result
        char *name_utf8 = utf16le_to_utf8(description_start, desc_len_chars * sizeof(uint16_t));
        if (name_utf8)
        {
            printf("Name: %s\n", name_utf8);
            free(name_utf8); // Free the allocated memory
        }
        else
        {
            printf("Name: (Error converting description)\n");
        }

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