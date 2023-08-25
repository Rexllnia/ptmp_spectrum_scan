#include "spctrm_scn_debug.h"

int spectrm_scn_debug_init(void)
{
    if (dbg_init(SPCTRM_SCN_DEBUG, SPCTRM_SCN_FILE, SPCTRM_SCN_DEBUG_SIZE) != 0) {
        fprintf(stderr, "ERROR: debug init failed in %s on %d lines\n", __FILE__, __LINE__);
        return FAIL;
    }

    g_dbg_id = dbg_module_reg("main");
    if(g_dbg_id < 0) {
        fprintf(stderr, "ERROR: register debug module failed in %s on %d lines\n", __FILE__, __LINE__);
        return FAIL;
    }

    SPCTRM_SCN_DBG_FILE("\n\n\n------------------------- Start spectrum_scan -------------------------\n");
    SPCTRM_SCN_DBG_FILE("\ndbg_init() success\n");

    return SUCCESS;
}


