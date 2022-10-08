/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <curl/curlver.h>
#if LIBCURL_VERSION_NUM >= 0x073500
#error curl-compat feature requires building with libcurl 7.52.x or older
#endif
void curl_easy_cleanup() {}
void curl_easy_duphandle() {}
void curl_easy_getinfo() {}
void curl_easy_init() {}
void curl_easy_setopt() {}
void curl_easy_strerror() {}
void curl_global_cleanup() {}
void curl_global_init() {}
void curl_global_init_mem() {}
void curl_multi_add_handle() {}
void curl_multi_cleanup() {}
void curl_multi_fdset() {}
void curl_multi_info_read() {}
void curl_multi_init() {}
void curl_multi_perform() {}
void curl_multi_remove_handle() {}
void curl_multi_strerror() {}
void curl_multi_timeout() {}
void curl_slist_append() {}
void curl_slist_free_all() {}
