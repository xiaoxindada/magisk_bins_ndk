#include <gtest/gtest.h>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/stringprintf.h>

#include "android_internal.h"
#include "label_internal.h"

using android::base::StringPrintf;
using android::base::WriteStringToFile;
using std::string;

class AndroidSELinuxTest : public ::testing::Test {
    protected:
	const char* kUnknownDomain = "u:r:unknown";
	TemporaryDir tdir_;

	int LoadSeAppContexts(string content)
	{
		string seapp_contexts = StringPrintf("%s/seapp_contexts", tdir_.path);
		WriteStringToFile(content, seapp_contexts);
		path_alts_t seapp_paths = {
			.paths = {
				{ seapp_contexts.c_str() }
			},
			.partitions = {
				"system"
			}
		};
		return seapp_context_reload_internal(&seapp_paths);
	}

        /* Resolve the context for a specific `seinfo` and ensures that it matches
         * `expected`. If `expected` is NULL, ensures that the context is not modified
         */
        void ExpectContextForSeInfo(const char* seinfo, const char* expected)
	{
		context_t ctx = context_new(kUnknownDomain);
		int ret = seapp_context_lookup_internal(SEAPP_DOMAIN, 10001, false, seinfo, "com.android.test", ctx);
		EXPECT_EQ(ret, 0);
		if (!expected) {
			expected = kUnknownDomain;
		}
		EXPECT_STREQ(context_str(ctx), expected);
		context_free(ctx);
	}
};

TEST_F(AndroidSELinuxTest, LoadAndLookupServiceContext)
{
	string service_contexts =
		StringPrintf("%s/service_contexts", tdir_.path);
	string unused_service_contexts =
		StringPrintf("%s/unused_contexts", tdir_.path);
	string vendor_contexts =
		StringPrintf("%s/vendor_service_contexts", tdir_.path);

	WriteStringToFile("account  u:object_r:account_service:s0\n",
			  service_contexts);
	WriteStringToFile("ignored  u:object_r:ignored_service:s0\n",
			  unused_service_contexts);
	WriteStringToFile(
		"android.hardware.power.IPower/default  u:object_r:hal_power_service:s0\n",
		vendor_contexts);

	const path_alts_t service_paths = { .paths = {
		{ service_contexts.c_str(), unused_service_contexts.c_str() },
		{ vendor_contexts.c_str() }
	}};

	struct selabel_handle *handle = context_handle(
		SELABEL_CTX_ANDROID_SERVICE, &service_paths, "test_service");
	EXPECT_NE(handle, nullptr);

	char *tcontext;
	EXPECT_EQ(selabel_lookup_raw(handle, &tcontext, "foobar",
				     SELABEL_CTX_ANDROID_SERVICE),
		  -1);

	EXPECT_EQ(selabel_lookup_raw(handle, &tcontext, "account",
				     SELABEL_CTX_ANDROID_SERVICE),
		  0);
	EXPECT_STREQ(tcontext, "u:object_r:account_service:s0");
	free(tcontext);

	EXPECT_EQ(selabel_lookup_raw(handle, &tcontext, "ignored",
				     SELABEL_CTX_ANDROID_SERVICE),
		  -1);

	EXPECT_EQ(selabel_lookup_raw(handle, &tcontext,
				     "android.hardware.power.IPower/default",
				     SELABEL_CTX_ANDROID_SERVICE),
		  0);
	EXPECT_STREQ(tcontext, "u:object_r:hal_power_service:s0");
	free(tcontext);

	selabel_close(handle);
}

TEST_F(AndroidSELinuxTest, FailLoadingServiceContext)
{
	string service_contexts =
		StringPrintf("%s/service_contexts", tdir_.path);

	WriteStringToFile("garbage\n", service_contexts);

	const path_alts_t service_paths = { .paths = {
		{ service_contexts.c_str() }
	}};

	struct selabel_handle *handle = context_handle(
		SELABEL_CTX_ANDROID_SERVICE, &service_paths, "test_service");
	EXPECT_EQ(handle, nullptr);
}

TEST_F(AndroidSELinuxTest, LoadAndLookupSeAppContext)
{
	int ret = LoadSeAppContexts(
		"# some comment\n"
		"user=_app seinfo=platform domain=platform_app type=app_data_file levelFrom=user\n"
	);

	EXPECT_EQ(ret, 0);

	context_t ctx = context_new("u:r:unknown");
	ret = seapp_context_lookup_internal(SEAPP_DOMAIN, 10001, false, "platform", "com.android.test1", ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_STREQ(context_str(ctx), "u:r:platform_app:s0:c512,c768");
	context_free(ctx);

	ctx = context_new("u:r:unknown_data_file");
	ret = seapp_context_lookup_internal(SEAPP_TYPE, 10001, false, "platform", "com.android.test1", ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_STREQ(context_str(ctx), "u:r:app_data_file:s0:c512,c768");
	context_free(ctx);
}

TEST_F(AndroidSELinuxTest, LoadAndLookupSeAppContextBooleanDefault)
{
	int ret = LoadSeAppContexts(
		"user=_app domain=catchall_app type=x levelFrom=user\n"
	);

	EXPECT_EQ(ret, 0);

	ExpectContextForSeInfo("default:privapp:partition=system:complete", "u:r:catchall_app:s0:c512,c768");
	ExpectContextForSeInfo("default:ephemeralapp:partition=system:complete", "u:r:catchall_app:s0:c512,c768");

	ExpectContextForSeInfo("default:isolatedComputeApp:partition=system:complete", nullptr);
	ExpectContextForSeInfo("default:isSdkSandboxAudit:partition=system:complete", nullptr);
	ExpectContextForSeInfo("default:isSdkSandboxNext:partition=system:complete", nullptr);
	ExpectContextForSeInfo("default:fromRunAs:partition=system:complete", nullptr);
}

TEST_F(AndroidSELinuxTest, LoadAndLookupSeAppContextBooleanFalse)
{
	int ret = LoadSeAppContexts(
		"user=_app isPrivApp=false domain=noprivapp type=x levelFrom=user\n"
		"user=_app isEphemeralApp=false domain=noephemeralapp type=x levelFrom=user\n"
		"user=_app domain=catchall_app type=x levelFrom=user\n"
	);

	EXPECT_EQ(ret, 0);

	ExpectContextForSeInfo("default:privapp:partition=system:complete", "u:r:noephemeralapp:s0:c512,c768");
	ExpectContextForSeInfo("default:ephemeralapp:partition=system:complete", "u:r:noprivapp:s0:c512,c768");
	// isEphemeralApp has precedence over isPrivApp.
	ExpectContextForSeInfo("default:partition=system:complete", "u:r:noephemeralapp:s0:c512,c768");

        // For the boolean selectors with a default value, check that the
        // loading fail (as this is a duplicate of the catchall).
        string defaultFalseBooleans[] = { "isIsolatedComputeApp", "isSdkSandboxAudit", "isSdkSandboxNext", "fromRunAs" };
	for (int i=0; i < arraysize(defaultFalseBooleans); i++) {
		string seapp_contexts =
			"user=_app " + defaultFalseBooleans[i] + "=false domain=y type=x levelFrom=user\n"
			"user=_app domain=catchall_app type=x levelFrom=user\n";
		ret = LoadSeAppContexts(seapp_contexts);
		EXPECT_EQ(ret, -1); // we expect a failure because of the duplicate.
	}
}

TEST_F(AndroidSELinuxTest, LoadAndLookupSeAppContextBooleanTrue)
{
	int ret = LoadSeAppContexts(
		"user=_app isPrivApp=true domain=privapp type=x levelFrom=user\n"
		"user=_app isEphemeralApp=true domain=ephemeralapp type=x levelFrom=user\n"
		"user=_app isIsolatedComputeApp=true domain=isolatedapp type=x levelFrom=user\n"
		"user=_app isSdkSandboxAudit=true domain=sdk_audit type=x levelFrom=user\n"
		"user=_app isSdkSandboxNext=true domain=sdk_next type=x levelFrom=user\n"
		"user=_app fromRunAs=true domain=runas type=x levelFrom=user\n"
		"user=_app domain=catchall_app type=x levelFrom=user\n"
	);

	EXPECT_EQ(ret, 0);

	ExpectContextForSeInfo("default:privapp:partition=system:complete", "u:r:privapp:s0:c512,c768");
	ExpectContextForSeInfo("default:ephemeralapp:partition=system:complete", "u:r:ephemeralapp:s0:c512,c768");
	ExpectContextForSeInfo("default:isolatedComputeApp:partition=system:complete", "u:r:isolatedapp:s0:c512,c768");
	ExpectContextForSeInfo("default:isSdkSandboxAudit:partition=system:complete", "u:r:sdk_audit:s0:c512,c768");
	ExpectContextForSeInfo("default:isSdkSandboxNext:partition=system:complete", "u:r:sdk_next:s0:c512,c768");
	ExpectContextForSeInfo("default:fromRunAs:partition=system:complete", "u:r:runas:s0:c512,c768");

	ExpectContextForSeInfo("default:partition=system:complete", "u:r:catchall_app:s0:c512,c768");
}

TEST(AndroidSeAppTest, ParseValidSeInfo)
{
	struct parsed_seinfo info;
	memset(&info, 0, sizeof(info));

	string seinfo = "default:privapp:targetSdkVersion=10000:partition=system:complete";
	int ret = parse_seinfo(seinfo.c_str(), &info);

	EXPECT_EQ(ret, 0);
	EXPECT_STREQ(info.base, "default");
	EXPECT_EQ(info.targetSdkVersion, 10000);
	EXPECT_EQ(info.is, IS_PRIV_APP);
	EXPECT_EQ(info.isPreinstalledApp, true);
	EXPECT_STREQ(info.partition, "system");

	seinfo = "platform:ephemeralapp:partition=system:complete";
	ret = parse_seinfo(seinfo.c_str(), &info);

	EXPECT_EQ(ret, 0);
	EXPECT_STREQ(info.base, "platform");
	EXPECT_EQ(info.targetSdkVersion, 0);
	EXPECT_EQ(info.is, IS_EPHEMERAL_APP);
	EXPECT_EQ(info.isPreinstalledApp, true);
	EXPECT_STREQ(info.partition, "system");

	seinfo = "bluetooth";
	ret = parse_seinfo(seinfo.c_str(), &info);

	EXPECT_EQ(ret, 0);
	EXPECT_STREQ(info.base, "bluetooth");
	EXPECT_EQ(info.targetSdkVersion, 0);
	EXPECT_EQ(info.isPreinstalledApp, false);
	EXPECT_EQ(info.is, 0);
}

TEST(AndroidSeAppTest, ParseInvalidSeInfo)
{
	struct parsed_seinfo info;

	string seinfo = "default:targetSdkVersion:complete";
	int ret = parse_seinfo(seinfo.c_str(), &info);
	EXPECT_EQ(ret, -1);

	seinfo = "default:targetSdkVersion=:complete";
	ret = parse_seinfo(seinfo.c_str(), &info);
	EXPECT_EQ(ret, -1);
}

TEST(AndroidSeAppTest, ParseOverflow)
{
	struct parsed_seinfo info;

	string seinfo = std::string(255, 'x');
	int ret = parse_seinfo(seinfo.c_str(), &info);
	EXPECT_EQ(ret, 0);
	EXPECT_STREQ(info.base, seinfo.c_str());

	seinfo = std::string(256, 'x');
	ret = parse_seinfo(seinfo.c_str(), &info);
	EXPECT_EQ(ret, -1);
}

TEST(AndroidSELinuxPathTest, IsAppDataPath)
{
	EXPECT_TRUE(is_app_data_path("/data/data"));
	EXPECT_TRUE(is_app_data_path("/data/user/0"));

	EXPECT_FALSE(is_app_data_path("/data"));
}

TEST(AndroidSELinuxPathTest, IsCredentialEncryptedPath)
{
	EXPECT_TRUE(is_credential_encrypted_path("/data/system_ce/0"));
	EXPECT_TRUE(is_credential_encrypted_path("/data/system_ce/0/backup"));
	EXPECT_TRUE(is_credential_encrypted_path("/data/misc_ce/0"));
	EXPECT_TRUE(is_credential_encrypted_path("/data/misc_ce/0/apexdata"));
	EXPECT_TRUE(is_credential_encrypted_path("/data/vendor_ce/0"));
	EXPECT_TRUE(is_credential_encrypted_path("/data/vendor_ce/0/data"));

	EXPECT_FALSE(is_credential_encrypted_path("/data"));
	EXPECT_FALSE(is_credential_encrypted_path("/data/data"));
	EXPECT_FALSE(is_credential_encrypted_path("/data/user/0"));
}

TEST(AndroidSELinuxPathTest, ExtractPkgnameAndUserid)
{
	char *pkgname = NULL;
	unsigned int userid;

	EXPECT_EQ(extract_pkgname_and_userid("/data/", &pkgname, &userid), -1);

	char const* path = "/data/user/0/com.android.myapp";
	EXPECT_EQ(extract_pkgname_and_userid(path, &pkgname, &userid), 0);
	EXPECT_STREQ("com.android.myapp", pkgname);
	EXPECT_EQ(userid, 0);
	free(pkgname);
	pkgname = NULL;

	path = "/data/user/0/com.android.myapp/som/subdir";
	EXPECT_EQ(extract_pkgname_and_userid(path, &pkgname, &userid), 0);
	EXPECT_STREQ("com.android.myapp", pkgname);
	EXPECT_EQ(userid, 0);
	free(pkgname);
	pkgname = NULL;

	path = "/data/data/com.android.myapp2";
	EXPECT_EQ(extract_pkgname_and_userid(path, &pkgname, &userid), 0);
	EXPECT_STREQ("com.android.myapp2", pkgname);
	EXPECT_EQ(userid, 0);
	free(pkgname);
	pkgname = NULL;

	path = "/data/misc_de/10/sdksandbox/com.android.myapp3";
	EXPECT_EQ(extract_pkgname_and_userid(path, &pkgname, &userid), 0);
	EXPECT_STREQ("com.android.myapp3", pkgname);
	EXPECT_EQ(userid, 10);
	free(pkgname);
	pkgname = NULL;
}
