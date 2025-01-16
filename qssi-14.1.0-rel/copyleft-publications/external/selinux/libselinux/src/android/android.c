#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>

#include <log/log.h>
#include <selinux/android.h>
#include <selinux/label.h>

#include "android_internal.h"
#include "callbacks.h"

#ifdef __ANDROID_VNDK__
#ifndef LOG_EVENT_STRING
#define LOG_EVENT_STRING(...)
#endif  // LOG_EVENT_STRING
#endif  // __ANDROID_VNDK__

#define TRACE_MARKER_PATH "/sys/kernel/tracing/instances/libselinux/trace_marker"

static void trace_log(const char *fmt, ...)
{
	char buf[PAGE_SIZE];
	va_list ap;
	static int fd = -1;
	static bool inuse = true;
	ssize_t len, ret;
	struct stat stats;

	if (inuse) {
		if (fd == -1) {
			ret = lstat(TRACE_MARKER_PATH, &stats);
			if (ret) {
				inuse = false;
				ALOGE("Error lstat disabled " TRACE_MARKER_PATH ";res=%d errno=%d",
				      ret, errno);
				return;
			}
		}
	} else {
		return;
	}

	if (fd < 0) {
		fd = open(TRACE_MARKER_PATH, O_WRONLY | O_CLOEXEC);
		if (fd < 0) {
			ALOGE("Error opening " TRACE_MARKER_PATH "; errno=%d",
			      errno);
			return;
		}
	}

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	len = strlen(buf);
	ret = TEMP_FAILURE_RETRY(write(fd, buf, len));
	if (ret < 0) {
		if (errno != EBADF) {
			ALOGE("Error writing " TRACE_MARKER_PATH ";errno=%d", errno);
			close(fd);
			fd = -1;
		}
	} else {
		if (ret < len) {
			ALOGE("Short write on " TRACE_MARKER_PATH "; length=%zd", ret);
		}
	}
}

static const path_alts_t service_context_paths = { .paths = {
	{
		"/system/etc/selinux/plat_service_contexts",
		"/plat_service_contexts"
	},
	{
		"/dev/selinux/apex_service_contexts"
	},
	{
		"/system_ext/etc/selinux/system_ext_service_contexts",
		"/system_ext_service_contexts"
	},
	{
		"/product/etc/selinux/product_service_contexts",
		"/product_service_contexts"
	},
	{
		"/vendor/etc/selinux/vendor_service_contexts",
		"/vendor_service_contexts"
	},
	{
		"/odm/etc/selinux/odm_service_contexts",
	}
}};

static const path_alts_t hwservice_context_paths = { .paths = {
	{
		"/system/etc/selinux/plat_hwservice_contexts",
		"/plat_hwservice_contexts"
	},
	{
		"/system_ext/etc/selinux/system_ext_hwservice_contexts",
		"/system_ext_hwservice_contexts"
	},
	{
		"/product/etc/selinux/product_hwservice_contexts",
		"/product_hwservice_contexts"
	},
	{
		"/vendor/etc/selinux/vendor_hwservice_contexts",
		"/vendor_hwservice_contexts"
	},
	{
		"/odm/etc/selinux/odm_hwservice_contexts",
		"/odm_hwservice_contexts"
	},
}};

static const path_alts_t vndservice_context_paths = { .paths = {
	{
		"/vendor/etc/selinux/vndservice_contexts",
		"/vndservice_contexts"
	}
}};

static const path_alts_t keystore2_context_paths = { .paths = {
	{
		"/system/etc/selinux/plat_keystore2_key_contexts",
		"/plat_keystore2_key_contexts"
	},
	{
		"/system_ext/etc/selinux/system_ext_keystore2_key_contexts",
		"/system_ext_keystore2_key_contexts"
	},
	{
		"/product/etc/selinux/product_keystore2_key_contexts",
		"/product_keystore2_key_contexts"
	},
	{
		"/vendor/etc/selinux/vendor_keystore2_key_contexts",
		"/vendor_keystore2_key_contexts"
	}
}};

size_t find_existing_files(
		const path_alts_t *path_sets,
		const char* paths[MAX_CONTEXT_PATHS])
{
	size_t i, j, len = 0;
	for (i = 0; i < MAX_CONTEXT_PATHS; i++) {
		for (j = 0; j < MAX_ALT_CONTEXT_PATHS; j++) {
			const char* file = path_sets->paths[i][j];
			if (file && access(file, R_OK) != -1) {
				paths[len++] = file;
				/* Within each set, only the first valid entry is used */
				break;
			}
		}
	}
	return len;
}

void paths_to_opts(const char* paths[MAX_CONTEXT_PATHS],
		size_t npaths,
		struct selinux_opt* const opts)
{
	for (size_t i = 0; i < npaths; i++) {
		opts[i].type = SELABEL_OPT_PATH;
		opts[i].value = paths[i];
	}
}

struct selabel_handle* initialize_backend(
		unsigned int backend,
		const char* name,
		const struct selinux_opt* opts,
		size_t nopts)
{
		struct selabel_handle* sehandle;

		sehandle = selabel_open(backend, opts, nopts);

		if (!sehandle) {
				selinux_log(SELINUX_ERROR, "%s: Error getting %s handle (%s)\n",
								__FUNCTION__, name, strerror(errno));
				return NULL;
		}
		selinux_log(SELINUX_INFO, "SELinux: Loaded %s context from:\n", name);
		for (unsigned i = 0; i < nopts; i++) {
			if (opts[i].type == SELABEL_OPT_PATH)
				selinux_log(SELINUX_INFO, "		%s\n", opts[i].value);
		}
		return sehandle;
}

struct selabel_handle* context_handle(
		unsigned int backend,
		const path_alts_t *context_paths,
		const char *name)
{
	const char* existing_paths[MAX_CONTEXT_PATHS];
	struct selinux_opt opts[MAX_CONTEXT_PATHS];
	int size = 0;

	size = find_existing_files(context_paths, existing_paths);
	paths_to_opts(existing_paths, size, opts);

	return initialize_backend(backend, name, opts, size);
}

struct selabel_handle* selinux_android_service_context_handle(void)
{
	return context_handle(SELABEL_CTX_ANDROID_SERVICE, &service_context_paths, "service");
}

struct selabel_handle* selinux_android_hw_service_context_handle(void)
{
	return context_handle(SELABEL_CTX_ANDROID_SERVICE, &hwservice_context_paths, "hwservice");
}

struct selabel_handle* selinux_android_vendor_service_context_handle(void)
{
	return context_handle(SELABEL_CTX_ANDROID_SERVICE, &vndservice_context_paths, "vndservice");
}

struct selabel_handle* selinux_android_keystore2_key_context_handle(void)
{
	return context_handle(SELABEL_CTX_ANDROID_KEYSTORE2_KEY, &keystore2_context_paths, "keystore2");
}

static void __selinux_log_callback(bool add_to_event_log, int type, const char *fmt, va_list ap) {
	int priority;
	char *strp;

	switch(type) {
	case SELINUX_WARNING:
		priority = ANDROID_LOG_WARN;
		break;
	case SELINUX_INFO:
		priority = ANDROID_LOG_INFO;
		break;
	default:
		priority = ANDROID_LOG_ERROR;
		break;
	}

	int len = vasprintf(&strp, fmt, ap);
	if (len < 0) {
		return;
	}

	/* libselinux log messages usually contain a new line character, while
	 * Android LOG() does not expect it. Remove it to avoid empty lines in
	 * the log buffers.
	 */
	if (len > 0 && strp[len - 1] == '\n') {
		strp[len - 1] = '\0';
	}

	trace_log(strp);

	LOG_PRI(priority, "SELinux", "%s", strp);
	if (add_to_event_log) {
		LOG_EVENT_STRING(AUDITD_LOG_TAG, strp);
	}
	free(strp);
}

int selinux_log_callback(int type, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	__selinux_log_callback(true, type, fmt, ap);
	va_end(ap);
	return 0;
}

int selinux_vendor_log_callback(int type, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	__selinux_log_callback(false, type, fmt, ap);
	va_end(ap);
	return 0;
}
