#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(USE_SSL)
#include <openssl/sha.h>
#endif

typedef enum {
    mfh_type_cefdk_s1 = 0x00000000,
    mfh_type_cefdk_s2 = 0x00000002,
    mfh_type_cefdk_s1h = 0x00000001,
    mfh_type_cefdk_s2h = 0x00000003,
    mfh_type_cefdk_params = 0x00000004,
    mfh_type_plat_params = 0x00000005,
    mfh_type_bootloader = 0,
    mfh_type_kernel = 0,
    mfh_type_splash = 0,
    mfh_type_manifest = 0,
    mfh_type_sec_fw = 0,
    mfh_type_ramdisk = 0,
    mfh_type_ilp = 0,
    mfh_type_cefdk_cmds = 0,
    mfh_type_bl_params = 0,
    mfh_type_auto_sec_fw = 0,
    mfh_type_uc8051_fw = 0,
    mfh_type_psvn = 0,
    mfh_type_ip_params = 0x00000012,
    mfh_type_kernel_params = 0,
    mfh_type_arm_test = 0,
    mfh_type_script = 0x00000015,
    mfh_type_cefdk_s3 = 0x00000016,
    mfh_type_cefdk_s3h = 0x00000017,
    mfh_type_partition = 0,
    mfh_type_all = 0,
    mfh_type_cefdk = 0,
    mfh_type_illegal = 0,
    mfh_type_offset = 0,
    mfh_type_user_flash = 0xffffffff,
} mfh_type_t;

static const struct {
    const char* label;
    mfh_type_t type;
} mfh_item_types[] = {
    { /* @ 0xFAC13 */ "cefdk_s1",       mfh_type_cefdk_s1        },
    { /* @ 0xFAC2B */ "cefdk_s2",       mfh_type_cefdk_s2        },
    { /* @ 0xFAC43 */ "cefdk_s1h",      mfh_type_cefdk_s1h       },
    { /* @ 0xFAC5B */ "cefdk_s2h",      mfh_type_cefdk_s2h       },
    { /* @ 0xFAC73 */ "cefdk_params",   mfh_type_cefdk_params    },
    { /* @ 0xFAC8B */ "plat_params",    mfh_type_plat_params     },
    { /* @ 0xFACA3 */ "bootloader",     mfh_type_bootloader      }, /* tbd */
    { /* @ 0xFACBB */ "kernel",         mfh_type_kernel          }, /* tbd */
    { /* @ 0xFACD3 */ "splash",         mfh_type_splash          }, /* tbd */
    { /* @ 0xFACEB */ "manifest",       mfh_type_manifest        }, /* tbd */
    { /* @ 0xFAD03 */ "sec_fw",         mfh_type_sec_fw          }, /* tbd */
    { /* @ 0xFAD1B */ "ramdisk",        mfh_type_ramdisk         }, /* tbd */
    { /* @ 0xFAD33 */ "ilp",            mfh_type_ilp             }, /* tbd */
    { /* @ 0xFAD4B */ "cefdk_cmds",     mfh_type_cefdk_cmds      }, /* tbd */
    { /* @ 0xFAD63 */ "bl_params",      mfh_type_bl_params       }, /* tbd */
    { /* @ 0xFAD7B */ "auto_sec_fw",    mfh_type_auto_sec_fw     }, /* tbd */
    { /* @ 0xFAD93 */ "uc8051_fw",      mfh_type_uc8051_fw       }, /* tbd */
    { /* @ 0xFADAB */ "psvn",           mfh_type_psvn            }, /* tbd */
    { /* @ 0xFADC3 */ "ip_params",      mfh_type_ip_params       },
    { /* @ 0xFADDB */ "kernel_params",  mfh_type_kernel_params   }, /* tbd */
    { /* @ 0xFADF3 */ "arm_test",       mfh_type_arm_test        }, /* tbd */
    { /* @ 0xFAE0B */ "script",         mfh_type_script          },
    { /* @ 0xFAE23 */ "cefdk_s3",       mfh_type_cefdk_s3        },
    { /* @ 0xFAE3B */ "cefdk_s3h",      mfh_type_cefdk_s3h       },
    { /* @ 0xFAE53 */ "partition",      mfh_type_partition       }, /* tbd */
    { /* @ 0xFAE6B */ "all",            mfh_type_all             }, /* tbd */
    { /* @ 0xFAE83 */ "cefdk",          mfh_type_cefdk           }, /* tbd */
    { /* @ 0xFAE9B */ "illegal",        mfh_type_illegal         }, /* tbd */
    { /* @ 0xFAEB3 */ "user offset",    mfh_type_offset          }, /* tbd */
    { /* @ 0xFAECB */ "user flash",     mfh_type_user_flash      },
};

// https://www.intel.com/content/dam/support/us/en/documents/processors/quark/sb/quark_securebootprm_330234_001.pdf
// from Table 7:
typedef struct
{
    uint32_t version;
    uint32_t flags;
    uint32_t next_header_block;
    uint32_t flash_item_count;
    uint32_t boot_priority_list_count;
    uint32_t boot_index_and_flash_items[115];
    uint32_t signature[8]; /* CE: not per spec, but there's a sha256 of the above items */
} mfh_t;

// from Table 8:
typedef struct
{
    uint32_t type;
    uint32_t id; /* CE: not per spec */
    uint32_t flags; /* CE: not per spec */
    uint32_t offset;
    uint32_t length;
    uint32_t rsvd;
    uint32_t unk[2]; /* CE: not per spec */
} mfh_flash_item_t;


#define MFH_BLOCK_COUNT 4

/* this is where the MFH starts */
static uint32_t mfh_offset = 0x80000;

/* I think this is where it gets loaded in memory */
static uint32_t mfh_load_offset = 0x200000;

typedef struct
{
    mfh_flash_item_t *item;
    void* data;
} mfh_flash_item_with_data_t;

#if defined(USE_SSL)
int mfh_block_sign(const mfh_t * mfh, uint8_t signature[SHA256_DIGEST_LENGTH])
{
    SHA256_CTX sha256;
    int ret = 0;

    ret = SHA256_Init(&sha256);
    if (ret != 1) { 
        fprintf(stderr, "error: SHA256_Init error %d\n", ret);
        return -1;
    }

    ret = SHA256_Update(&sha256, (void*)mfh, sizeof(mfh_t) - SHA256_DIGEST_LENGTH);
    if (ret != 1) { 
        fprintf(stderr, "error: SHA256_Update error %d\n", ret);
        return -1;
    }

    ret = SHA256_Final(signature, &sha256);
    if (ret != 1) { 
        fprintf(stderr, "error: SHA256_Final error %d\n", ret);
        return -1;
    }
    return 0;
}
#endif

void dump_mfh(const mfh_t * mfh, const bool column_mode)
{
#if defined(USE_SSL)
        uint8_t signature[SHA256_DIGEST_LENGTH] = { 0 };
        mfh_block_sign(mfh, signature);
#endif

    if (column_mode) {

        const char* sign_text = "Unk";
#if defined(USE_SSL)
        if (!memcmp(signature, mfh->signature, SHA256_DIGEST_LENGTH))
            sign_text = "OK";
        else
            sign_text = "Err";
#endif

        printf("0x%.8x 0x%.8x 0x%.8x %.2d %.2d %-3s\n",
               mfh->version,
               mfh->flags,
               mfh->next_header_block,
               mfh->flash_item_count,
               mfh->boot_priority_list_count,
               sign_text);
    } else {
        printf(" Version: %d\n", mfh->version);
        printf(" Flags: 0x%.8x\n", mfh->flags);
        printf(" Next Header Block: 0x%.8x\n", mfh->next_header_block);
        printf(" Flash Item Count: %d\n", mfh->flash_item_count);
        printf(" Boot Priority List Count: %d\n", mfh->boot_priority_list_count);

#if defined(USE_SSL)
        if (!memcmp(signature, mfh->signature, SHA256_DIGEST_LENGTH))
            printf(" Signature: OK\n");
        else
            printf(" Signature: Not OK!!!\n");

        return;
        printf(" Signature: ");
        for (int i = 0; i < sizeof(mfh->signature); ++i) {
            printf("%.2x ", mfh->signature[i]);
        }
        printf("\n");

        printf(" Calculated Signature: ");
        for (int i = 0; i < sizeof(signature); ++i) {
            printf("%.2x ", signature[i]);
        }
        printf("\n");
#endif
    }
}

static const char* mfh_get_label_from_type(uint32_t type)
{
    for (size_t i = 0; i < sizeof(mfh_item_types)/sizeof(mfh_item_types[0]); i++) {
        if (mfh_item_types[i].type == (mfh_type_t)type) {
            return mfh_item_types[i].label;
        }
    }

    return "NO?";    
}

void dump_mfh_item(const mfh_flash_item_t* mfh_item, const bool column_mode)
{
    if (column_mode) {
        printf("%-20s 0x%.8x %.2d 0x%.8x 0x%.8x 0x%.8x\n", 
               mfh_get_label_from_type(mfh_item->type),
               mfh_item->type,
               mfh_item->id,
               mfh_item->flags,
               mfh_item->offset,
               mfh_item->length);
    } else {
        printf(" Type: 0x%.8x (%s)\n", mfh_item->type, mfh_get_label_from_type(mfh_item->type));
        printf(" id: 0x%.8x\n", mfh_item->id);
        printf(" flags: 0x%.8x\n", mfh_item->flags);
        printf(" offset: 0x%.8x\n", mfh_item->offset);
        printf(" length: 0x%.8x\n", mfh_item->length);
    }
}

void dump_mfh_script(const mfh_flash_item_with_data_t * mfh_item)
{
    /* script ends when character is 0xff. each line end with \0. */
    uint32_t length = mfh_item->item->length;
    uint32_t line = 0;
    const char* str = mfh_item->data;

    /* second condition is to bail out in the worst case scenario */
    while (length && (line < mfh_item->item->length)) {
        if ((uint8_t)*str == 0xff) {
            break;
        }
        printf(" line %d => '", line);

        int printed = printf("%s", str);
    
        printf("' (len = %d)\n", printed);

        length -= printed + 1;
        str += printed + 1;

        line++;
    }

    printf(" script uses %d bytes out of %d\n", (mfh_item->item->length - length), mfh_item->item->length);
}

int read_mfh_data(mfh_flash_item_with_data_t * mfh_item, FILE* fh)
{
    mfh_item->data = malloc(mfh_item->item->length);
    if (!mfh_item->data) {
        fprintf(stderr, "error: can't allocate %d bytes for item data\n", mfh_item->item->length);
        return -1;
    }

    /* I don't know why there's a 0x20000 offset on their numbers */
    fseek(fh, mfh_item->item->offset - mfh_load_offset, SEEK_SET);

    if (fread(mfh_item->data, 1, mfh_item->item->length, fh) != mfh_item->item->length) {
        fprintf(stderr, "error: can't read %d bytes for item data\n", mfh_item->item->length);
        free(mfh_item->data);
    }

    return 0;
}

void usage(void)
{
    printf("mfh-tool <things>\n");
}

int verb_info(mfh_t* mfh, FILE* fh)
{
    printf("MFH Blocks, items = %d:\n", MFH_BLOCK_COUNT);
    printf("   Version      Flags NextHdrBlk FI BP Sign\n");
    for (int block = 0; block < MFH_BLOCK_COUNT; ++block) {
        dump_mfh(&mfh[block], true);
    }

    mfh_flash_item_t *mfh_flash_item = NULL;

    printf("===========\n");
    printf("Now going to process each block's contents:\n");

    for (int block = 0; block < MFH_BLOCK_COUNT; ++block) {
        if (mfh[block].version != 1) {
            fprintf(stderr, "error: mfh block #%d contains a non-validated version %d\n", block, mfh[block].version);
            return -1;
        }

        if (mfh[block].boot_priority_list_count) {
            printf("===========\n");
            printf("MFH Block %d, boot priority items = %d\n", block, mfh[block].boot_priority_list_count);

            /* print the Boot Indexes */
            for (int i = 0; i < mfh[block].boot_priority_list_count; ++i) {
                printf("MFH Block %d, boot priority item %d, value = 0x%.8x\n", block, i, mfh[block].boot_index_and_flash_items[i]);
            }
        }

        /* skip the Boot Indexes uint32_t entries on the table to get to the Flash Items */
        mfh_flash_item = (mfh_flash_item_t*)&mfh[block].boot_index_and_flash_items[mfh[block].boot_priority_list_count];

        if (mfh[block].flash_item_count) {
            printf("===========\n");
            printf("MFH Block %d, items = %d\n", block, mfh[block].flash_item_count);
            printf("Type Label                 Type ID      Flags     Offset       Size\n");
            for (int i = 0; i < mfh[block].flash_item_count; ++i) {
                dump_mfh_item(mfh_flash_item, true);
                mfh_flash_item_with_data_t flash_item_with_data = { mfh_flash_item , NULL};

                switch (mfh_flash_item->type) {
                    case mfh_type_script:
                        if (read_mfh_data(&flash_item_with_data, fh)) {
                            /* error */
                            continue;
                        }
                        printf("===========\n");
                        printf("MFH Block %d, 'script':\n", block);
                        dump_mfh_script(&flash_item_with_data);
                        printf("===========\n");

                        free(flash_item_with_data.data);
                        break;
                    default:
                        break;
                }
                /* next */
                mfh_flash_item += 1;
            }
        }
    }

    return 0;
}

int verb_dump_path(mfh_t* mfh, FILE* fh, const char* virtual_path, const char* output_path)
{

}

int main(int argc, char** argv)
{
    enum {
        VERB_INFO,
        VERB_PRINT_SCRIPT,
        VERB_DUMP_PATH
    } verb_action = VERB_INFO;

    FILE* fh = NULL;
    const char* path = NULL;
    const char* dump_path = NULL;
    const char* dump_output_file = NULL;

    if (argc == 2) {
        verb_action = VERB_INFO;
        path = argv[1];
    } else if (argc == 3) {
        if (!strcmp(argv[1], "dump")) {
            fprintf(stderr, "ERROR: specify the path of the section and the output file\n");
            usage();
            return -1;
        } else if (!strcmp(argv[1], "printscript")) {
            verb_action = VERB_PRINT_SCRIPT;
            path = argv[2];
        } else if (!strcmp(argv[1], "info")) {
            verb_action = VERB_INFO;
            path = argv[2];
        } else {
            fprintf(stderr, "ERROR: unrecognized verb '%s'\n", argv[1]);
            usage();
            return -1;
        }
    } else if (argc == 4) {
        if (!strcmp(argv[1], "dump")) {
            fprintf(stderr, "ERROR: specify the path of the section and the output file\n");
            usage();
            return -1;
        } else {
            fprintf(stderr, "ERROR: unrecognized verb '%s'\n", argv[1]);
            usage();
            return -1;
        }
    } else if (argc == 5) {
        if (!strcmp(argv[1], "dump")) {
            verb_action = VERB_DUMP_PATH;
            dump_path = argv[2];
            dump_output_file = argv[3];
        } else {
            fprintf(stderr, "ERROR: unrecognized verb '%s'\n", argv[1]);
            usage();
            return -1;
        }
    } else {
        fprintf(stderr, "ERROR: arguments don't match any available option\n");
        usage();
        return -1;
    }

    mfh_t mfhs[MFH_BLOCK_COUNT] __attribute__((aligned(64)));

    fh = fopen(path, "rb");
    if (!fh) {
        fprintf(stderr, "ERROR: can't open file '%s'\n", path);
        return -1;
    }

    fseek(fh, mfh_offset, SEEK_SET);
    fread(&mfhs, sizeof(mfhs), 1, fh);

    int ret = 0;
    switch (verb_action)
    {
        case VERB_INFO:
            ret = verb_info(mfhs, fh);
            break;

        case VERB_DUMP_PATH:
            ret = verb_dump_path(mfhs, fh, dump_path, dump_output_file);
            break;

        default:
            break;
    }

    fclose(fh);

    return ret;
}
