#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <sstream>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <getopt.h>
#include <mntent.h>
#include <libgen.h>
#include <dirent.h>
#include <stdarg.h>
#include <fcntl.h>

static void
logi(char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fputs("[INFO] ", stdout);
	vprintf(fmt, ap);
	va_end(ap);
}

static void
logw(char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fputs("[WARN] ", stderr);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static bool
is_directory_exists(const std::string& dir)
{
	struct stat sb;

	int ret = stat(dir.c_str(), &sb);
	if (ret != 0)
		return false;

	if (!S_ISDIR(sb.st_mode))
		return false;

	return true;
}

static std::vector<std::string>
default_new_directories()
{
	std::vector<std::string> dirs;

	dirs.push_back("etc");
	dirs.push_back("run");
	dirs.push_back("usr");
	dirs.push_back("var/log");

	return dirs;
}

static std::vector<std::string>
default_temp_directories()
{
	std::vector<std::string> dirs;

	dirs.push_back("tmp");
	dirs.push_back("run/lock");
	dirs.push_back("var/tmp");

	return dirs;
}

static std::vector<std::string>
default_bind_directories()
{
	std::vector<std::string> tmp;

	tmp.push_back("bin");
	tmp.push_back("etc/alternatives");
	tmp.push_back("etc/pki/tls/certs");
	tmp.push_back("etc/pki/ca-trust");
	tmp.push_back("etc/ssl/certs");
	tmp.push_back("lib");
	tmp.push_back("lib64");
	tmp.push_back("sbin");
	tmp.push_back("usr/bin");
	tmp.push_back("usr/include");
	tmp.push_back("usr/lib");
	tmp.push_back("usr/lib64");
	tmp.push_back("usr/libexec");
	tmp.push_back("usr/sbin");
	tmp.push_back("usr/share");
	tmp.push_back("usr/src");

	std::vector<std::string> dirs;
	for (const auto& d : tmp) {
		if (is_directory_exists(std::string("/") + d))
			dirs.push_back(d);
	}

	return dirs;
}

static std::vector<std::string>
default_copied_files()
{
	std::vector<std::string> files;
	files.push_back("etc/group");
	files.push_back("etc/passwd");
	files.push_back("etc/resolv.conf");
	files.push_back("etc/hosts");

	return files;
}

static void usage()
{
	std::cout << "Usage: jailing-c [options] command cmd_arg..."
		  << "\n\n"
		  << "\t--bind: "
		  << "\t--bind: "
		  << "\t--bind: "
		  << "\t--bind: "
		  << "\t--bind: "
		  << "\t--bind: "
		  << "\t--bind: "
		  << std::endl;
	std::exit(1);
}

static void
validate_root(const std::string& root)
{
	if (root.empty()) {
		std::cerr << "'--root' is not specified" << std::endl;
		std::exit(1);
	}

	if (root.front() != '/') {
		std::cerr << "'--root' must be an absolute path" << std::endl;
		std::exit(1);
	}

	logi("chroot directory '%s' is valid\n", root.c_str());
}

static std::vector<std::string>
mounted_directories(void)
{
	FILE *fp = setmntent("/proc/mounts", "r");
	if (fp == nullptr) {
		std::perror("setmntent");
		std::exit(1);
	}

	std::vector<std::string> entries;
	mntent *entry;
	while((entry = getmntent(fp)) != nullptr) {
		entries.push_back(static_cast<const char*>(entry->mnt_dir));
	}

	return entries;
}

static std::vector<std::string>
filter_in_root_directory(const std::vector<std::string>& dirs, const std::string& root)
{
	std::vector<std::string> filtered;
	for (const auto& dir : dirs) {
		if (std::equal(root.begin(), root.end(), dir.begin()))
			filtered.push_back(dir);
	}

	return filtered;
}

static void do_umount(const std::string& root)
{
	if (!is_directory_exists(root)) {
		std::cerr << "root='" << root << "'"
			  << " does not exist, cowardly refusing to umount"
			  << std::endl;
		std::exit(1);
	}

	std::vector<std::string> dirs = mounted_directories();
	for (const auto& dir : filter_in_root_directory(dirs, root)) {
		std::cout << "Unmount: " << dir << std::endl;
		int ret = umount(dir.c_str());
		if (ret != 0) {
			std::perror("umount");
			std::exit(1);
		}
	}
}

static void
mkdir_p(const char *path)
{
	struct stat sb;
	std::string tmp(path);
	const char *parent = dirname(const_cast<char*>(tmp.c_str()));
	int ret = stat(path, &sb);
	if (ret == 0 && S_ISDIR(sb.st_mode))
		return;

	ret = stat(parent, &sb);
	if (ret != 0) {
		mkdir_p(parent);
	}

	ret = mkdir(path, 0755);
	if (ret != 0) {
		perror("mkdir");
		std::exit(1);
	}

	logi("Success mkdir '%s'\n", path);
}

static void
create_directories(const std::string& root, const std::vector<std::string>& dirs)
{
	std::string tmp;

	for (const auto& dir : dirs) {
		std::string tmp(root + "/" + dir);
		mkdir_p(tmp.c_str());
	}
}

static void
set_permissions(const std::string& root, const std::vector<std::string>& dirs)
{
	for (const auto& dir : dirs) {
		std::string tmp(root + "/" + dir);
		int ret = chmod(tmp.c_str(), 01777);
		if (ret != 0) {
			perror("chmod");
			std::cerr << "failed chmod to " << tmp << "";
			std::exit(1);
		}

		logi("Change permission: %s\n", tmp.c_str());
	}
}

static void
copy_permissions(const std::string& src, const std::string& dst)
{
	struct stat st;
	int ret = stat(src.c_str(), &st);
	if (ret != 0) {
		std::perror("stat");
		std::exit(1);
	}

	ret = chmod(dst.c_str(), st.st_mode);
	if (ret != 0) {
		std::perror("stat");
		std::exit(1);
	}

	ret = chown(dst.c_str(), st.st_uid, st.st_gid);
	if (ret != 0) {
		std::perror("stat");
		std::exit(1);
	}
}

static void
copy_files(const std::string& root, const std::vector<std::string>& files)
{
	char buf[1024];

	// XXX Preserve permission like 'cp -p'
	for (const auto& file : files) {
		std::string src(std::string("/") + file);
		std::string dst(root + "/" + file);
		ssize_t len, lenw;

		logi("Copy '%s' to '%s'\n", src.c_str(), dst.c_str());

		int rd = open(src.c_str(), O_RDONLY);
		if (rd == -1) {
			std::perror("open");
			std::exit(1);
		}

		int wd = open(dst.c_str(), O_WRONLY|O_CREAT|O_TRUNC, 0644);
		if (wd == -1) {
			std::perror("open");
			std::exit(1);
		}

		while (true) {
		retry:
			len = read(rd, buf, sizeof(buf));
			if (len < 0) {
				if (errno == EINTR)
					goto retry;

				std::perror("read");
				std::exit(1);
			} else if (len == 0)
				break;

			lenw = write(wd, buf, len);
			if (lenw < 0) {
				std::perror("write");
				std::exit(1);
			}
		}

		copy_permissions(src, dst);
		close(rd);
		close(wd);
	}
}

static bool
is_symbolic_link(const std::string& path)
{
	struct stat sb;
	int ret = stat(path.c_str(), &sb);
	if (ret != 0)
		return false;

	return S_ISLNK(sb.st_mode);
}

static bool
is_empty(const std::string& dir)
{
	DIR *d = opendir(dir.c_str());
	if (d == nullptr) {
		perror("opendir");
		logw("Failed: opendir(%s)\n", dir.c_str());
		return false;
	}

	dirent *entry;
	while ((entry = readdir(d)) != nullptr) {
		std::string name(static_cast<const char*>(entry->d_name));
		if (!(name == "." || name == ".."))
			return false;
	}

	return true;
}

static void
mount_bind(const std::string& dst, const std::string& src, bool read_only)
{
	int flags = MS_BIND;
	if (read_only)
		flags |= MS_RDONLY;

	logw("# mount %s %s\n", src.c_str(), dst.c_str());

	// Linux kernel version must be 2.6.26 or higher.
	int ret = mount(src.c_str(), dst.c_str(), nullptr,flags, nullptr);
	if (ret != 0) {
		std::perror("mount");
		std::exit(1);
	}

	logi("# mount --bind %s %s %s\n",
	     read_only ? "-o ro" : "",
	     src.c_str(), dst.c_str());
}

static void
bind_directories(const std::string& root, const std::vector<std::string>& dirs)
{
	for (const auto& dir : dirs) {
		if (is_symbolic_link(dir)) {
			std::string tmp(root + "/" + dir);
			if (is_symbolic_link(tmp.c_str()))
				continue;

			// XXX Implement symbolic link
		} else {
			std::string tmp(root + "/" + dir);
			mkdir_p(tmp.c_str());

			if (is_empty(tmp)) {
				mount_bind(tmp, std::string("/") + dir, true);
			}
		}
	}
}

static void
touch_keep_file(const std::string& dir)
{
	std::string keep_file(dir + "/" + ".jailing.keep");

	// XXX Use C++ API
	int fd = open(keep_file.c_str(), O_WRONLY|O_CREAT, 0666);
	if (fd != 0) {
		std::perror("open");
		std::exit(1);
	}

	if (close(fd) != 0) {
		std::perror("close");
		std::exit(1);
	}

	logi("# touch %s\n", keep_file.c_str());
}

static void
bind_custom(const std::string& root, const std::vector<std::string>& dirs, bool readonly)
{
	for (const auto& dir : dirs) {
		if (is_empty(dir)) {
			touch_keep_file(dir);
		}

		std::string tmp(root + "/" + dir);
		mkdir_p(tmp.c_str());

		if (is_empty(tmp)) {
			mount_bind(tmp, dir, readonly);
		}
	}
}

static void
create_device_file(const std::string& dev_file, mode_t mode, dev_t id)
{
	int ret = mknod(dev_file.c_str(), mode, id);
	if (ret != 0) {
		std::perror("mknod");
		logw("Failed: create device file '%s'\n", dev_file.c_str());
		std::exit(1);
	}

	logi("# mknod %s\n", dev_file.c_str());
}

static void
create_device_files(const std::string& root)
{
	std::string dev_dir(root + "/dev");

	mkdir_p(dev_dir.c_str());
	create_device_file(dev_dir + "/null", S_IFCHR, makedev(1, 3));
	create_device_file(dev_dir + "/zero", S_IFCHR, makedev(1, 5));
	create_device_file(dev_dir + "/random", S_IFCHR, makedev(1, 9));
	create_device_file(dev_dir + "/urandom", S_IFCHR, makedev(1, 9));
}

static int
get_last_cap()
{
	int fd = open("/proc/sys/kernel/cap_last_cap", O_RDONLY);
	if (fd == -1) {
		std::perror("open");
		std::exit(1);
	}

	char buf[64];
	ssize_t len = read(fd, &buf, sizeof(buf));
	if (len == -1) {
		std::perror("read");
		std::exit(1);
	}

	return std::stoi(buf);
}

static const int KEEP_CAPS[] = {
	CAP_SETGID,
	CAP_SETUID,
	CAP_NET_BIND_SERVICE,
};

static bool
is_kept_capability(int cap)
{
	constexpr size_t CAPS = sizeof(KEEP_CAPS) / sizeof(int);
	for (size_t i = 0; i < CAPS; ++i) {
		if (cap == KEEP_CAPS[i])
			return true;
	}

	return false;
}

static void
drop_capabilities(int last_cap)
{
	for (int i = 0; i < last_cap; ++i) {
		if (is_kept_capability(i))
			continue;

		if (prctl(PR_CAPBSET_READ, i, 0, 0, 0) == -1)
			continue;

		if (prctl(PR_CAPBSET_DROP, i, 0, 0, 0) == -1) {
			std::perror("prctl");
			std::exit(1);
		}

		logi("# Drop capability%d\n", i);
	}
}

#ifdef NEVER
static void
create_symlink(const std::string& root)
{
	std::string lock(root + "/var/lock");
	int ret = symlink(lock.c_str(), "../run/lock");
	if (ret == -1) {
		std::perror("symlink");
		std::exit(1);
	}
}
#endif

static struct option long_options[] = {
	{"root",  required_argument, nullptr, 'r'},
	{"bind",  optional_argument, nullptr, 'b'},
	{"robind", optional_argument, nullptr, 'o'},
	{"umount", no_argument, nullptr, 'u'},
	{"help", no_argument, nullptr, 'h'},
	{nullptr, 0, nullptr, 0}
};

int main(int argc, char *argv[])
{
	std::string root;
	std::vector<std::string> bound_dirs, robound_dirs;
	bool umount_flag = false;

	while (true) {
		int option_index = 0;
		int c = getopt_long (argc, argv, "r:b:uh",
				     long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'r':
			root = std::string(static_cast<const char*>(optarg));
			break;
		case 'b':
			bound_dirs.push_back(static_cast<const char*>(optarg));
			break;
		case 'o':
			robound_dirs.push_back(static_cast<const char*>(optarg));
			break;
		case 'u':
			umount_flag = true;
			break;
		case 'h':
			usage();
			break;
		default:
			break;
		}
	}

	argc -= optind;
	argv += optind;

	std::cout << "Exec: root=" << root << std::endl;
	for (int i = 0; i < argc; ++i) {
		std::cout << i << ":" << argv[i] << std::endl;
	}
	std::cout << "End " << std::endl;

	validate_root(root);

	if (umount_flag) {
		do_umount(root);
		exit(0);
	}

	mkdir_p(root.c_str());
	create_directories(root, default_new_directories());

	std::vector<std::string> temp_dirs = default_temp_directories();
	create_directories(root, temp_dirs);
	set_permissions(root, temp_dirs);

	copy_files(root, default_copied_files());

	bind_directories(root, default_bind_directories());

	bind_custom(root, bound_dirs, false);
	bind_custom(root, robound_dirs, true);

	create_device_files(root);
//	create_symlink(root); // XXX need ??

	int max_cap_num = get_last_cap();

	if (chroot(root.c_str()) == -1) {
		std::perror("chroot");
		std::exit(1);
	}
	logi("chroot to '%s'\n", root.c_str());

	if (chdir("/") == -1) {
		std::perror("chdir");
		std::exit(1);
	}
	logi("chdir to '/' in jail\n");

	drop_capabilities(max_cap_num);

	logi("exec: %s\n", argv[0]);
	execvp(argv[0], argv);

	std::perror("execvp");
	logw("Never reach here\n");

	return 0;
}
