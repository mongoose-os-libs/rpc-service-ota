/*
 * Copyright (c) 2016 Cesanta Software Limited
 * All rights reserved
 */

#include "mgos_rpc_service_ota.h"

#include "mg_rpc.h"
#include "mgos_rpc.h"
#include "mgos_ota_http_client.h"

#include "common/cs_dbg.h"
#include "common/mg_str.h"
#include "mgos_mongoose.h"
#include "mgos_updater_common.h"
#include "mgos_utils.h"

static struct mg_rpc_request_info *s_update_req;

static void mg_rpc_updater_result(struct update_context *ctx) {
  if (s_update_req == NULL) return;
  mg_rpc_send_errorf(s_update_req, (ctx->result > 0 ? 0 : -1), ctx->status_msg);
  s_update_req = NULL;
}

static void handle_update_req(struct mg_rpc_request_info *ri, void *cb_arg,
                              struct mg_rpc_frame_info *fi,
                              struct mg_str args) {
  char *blob_url = NULL;
  struct json_token url_tok = JSON_INVALID_TOKEN;
  int commit_timeout = 0;
  struct update_context *ctx = NULL;

  LOG(LL_DEBUG, ("Update request received: %.*s", (int) args.len, args.p));

  const char *reply = "Malformed request";

  if (args.len == 0) {
    goto clean;
  }

  json_scanf(args.p, args.len, ri->args_fmt, &url_tok, &commit_timeout);

  if (url_tok.len == 0 || url_tok.type != JSON_TYPE_STRING) goto clean;

  LOG(LL_DEBUG, ("URL: %.*s commit_timeout: %d", url_tok.len, url_tok.ptr,
                 commit_timeout));

  /*
   * If user setup callback for updater, just call it.
   * User can start update with Sys.updater.start()
   */

  blob_url = calloc(1, url_tok.len + 1);
  if (blob_url == NULL) {
    LOG(LL_ERROR, ("Out of memory"));
    return;
  }

  memcpy(blob_url, url_tok.ptr, url_tok.len);

  ctx = updater_context_create();
  if (ctx == NULL) {
    reply = "Failed to init updater";
    goto clean;
  }
  ctx->fctx.commit_timeout = commit_timeout;
  ctx->result_cb = mg_rpc_updater_result;
  s_update_req = ri;

  mgos_ota_http_start(ctx, blob_url);
  free(blob_url);
  return;

clean:
  if (blob_url != NULL) free(blob_url);
  LOG(LL_ERROR, ("Failed to start update: %s", reply));
  mg_rpc_send_errorf(ri, -1, reply);
  ri = NULL;
  (void) cb_arg;
  (void) fi;
}

static void handle_commit_req(struct mg_rpc_request_info *ri, void *cb_arg,
                              struct mg_rpc_frame_info *fi,
                              struct mg_str args) {
  if (mgos_upd_commit()) {
    mg_rpc_send_responsef(ri, NULL);
  } else {
    mg_rpc_send_errorf(ri, -1, NULL);
  }
  ri = NULL;
  (void) cb_arg;
  (void) fi;
  (void) args;
}

static void handle_revert_req(struct mg_rpc_request_info *ri, void *cb_arg,
                              struct mg_rpc_frame_info *fi,
                              struct mg_str args) {
  if (mgos_upd_revert(false /* reboot */)) {
    mg_rpc_send_responsef(ri, NULL);
    mgos_system_restart_after(100);
  } else {
    mg_rpc_send_errorf(ri, -1, NULL);
  }
  ri = NULL;
  (void) cb_arg;
  (void) fi;
  (void) args;
}

static void handle_create_snapshot_req(struct mg_rpc_request_info *ri,
                                       void *cb_arg,
                                       struct mg_rpc_frame_info *fi,
                                       struct mg_str args) {
  const char *err_msg = NULL;
  int ret = -1;
  if (mgos_upd_is_committed()) {
    ret = mgos_upd_create_snapshot();
    if (ret >= 0) {
      bool set_as_revert = false;
      int commit_timeout = -1;
      json_scanf(args.p, args.len, ri->args_fmt, &set_as_revert,
                 &commit_timeout);
      if (set_as_revert) {
        struct mgos_upd_boot_state bs;
        if (mgos_upd_boot_get_state(&bs)) {
          bs.is_committed = false;
          bs.revert_slot = ret;
          if (mgos_upd_boot_set_state(&bs)) {
            if (commit_timeout >= 0 &&
                !mgos_upd_set_commit_timeout(commit_timeout)) {
              ret = -4;
              err_msg = "Failed to set commit timeout";
            }
          } else {
            ret = -3;
            err_msg = "Failed to set boot state";
          }
        } else {
          ret = -2;
          err_msg = "Failed to get boot state";
        }
      }
    } else {
      err_msg = "Failed to create snapshot";
    }
  } else {
    ret = -1;
    err_msg = "Cannot create snapshots in uncommitted state";
  }
  if (ret >= 0) {
    mg_rpc_send_responsef(ri, "{slot: %d}", ret);
  } else {
    mg_rpc_send_errorf(ri, ret, err_msg);
  }
  (void) cb_arg;
  (void) fi;
}

static void handle_get_boot_state_req(struct mg_rpc_request_info *ri,
                                      void *cb_arg,
                                      struct mg_rpc_frame_info *fi,
                                      struct mg_str args) {
  struct mgos_upd_boot_state bs;
  if (!mgos_upd_boot_get_state(&bs)) {
    mg_rpc_send_errorf(ri, -1, NULL);
  } else {
    mg_rpc_send_responsef(ri,
                          "{active_slot: %d, is_committed: %B, revert_slot: "
                          "%d, commit_timeout: %d}",
                          bs.active_slot, bs.is_committed, bs.revert_slot,
                          mgos_upd_get_commit_timeout());
  }
  (void) cb_arg;
  (void) fi;
  (void) args;
}

static void handle_set_boot_state_req(struct mg_rpc_request_info *ri,
                                      void *cb_arg,
                                      struct mg_rpc_frame_info *fi,
                                      struct mg_str args) {
  int ret = 0;
  struct mgos_upd_boot_state bs;
  if (mgos_upd_boot_get_state(&bs)) {
    int commit_timeout = -1;
    if (json_scanf(args.p, args.len, ri->args_fmt, &bs.active_slot,
                   &bs.is_committed, &bs.revert_slot, &commit_timeout) > 0) {
      ret = mgos_upd_boot_set_state(&bs) ? 0 : -3;
      if (ret == 0 && commit_timeout >= 0) {
        ret = mgos_upd_set_commit_timeout(commit_timeout) ? 0 : -4;
      }
    } else {
      ret = -2;
    }
  } else {
    ret = -1;
  }
  if (ret == 0) {
    mg_rpc_send_responsef(ri, NULL);
  } else {
    mg_rpc_send_errorf(ri, ret, NULL);
  }
  (void) cb_arg;
  (void) fi;
}

bool mgos_rpc_service_ota_init(void) {
  struct mg_rpc *mg_rpc = mgos_rpc_get_global();
  if (mg_rpc == NULL) return true;
  mg_rpc_add_handler(mg_rpc, "OTA.Update", "{url: %T, commit_timeout: %d}",
                     handle_update_req, NULL);
  mg_rpc_add_handler(mg_rpc, "OTA.Commit", "", handle_commit_req, NULL);
  mg_rpc_add_handler(mg_rpc, "OTA.Revert", "", handle_revert_req, NULL);
  mg_rpc_add_handler(mg_rpc, "OTA.CreateSnapshot",
                     "{set_as_revert: %B, commit_timeout: %d}",
                     handle_create_snapshot_req, NULL);
  mg_rpc_add_handler(mg_rpc, "OTA.GetBootState", "", handle_get_boot_state_req,
                     NULL);
  mg_rpc_add_handler(mg_rpc, "OTA.SetBootState",
                     "{active_slot: %d, is_committed: %B, revert_slot: %d, "
                     "commit_timeout: %d}",
                     handle_set_boot_state_req, NULL);
  return true;
}
