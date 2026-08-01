/*
 *  Hans - IP over ICMP
 *  Copyright (C) 2009 Friedrich Schöller <hans@schoeller.se>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "utility.h"
#include "exception.h"
#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

using std::string;

std::string Utility::formatIp(uint32_t ip)
{
    std::stringstream s;
    s << ((ip >> 24) & 0xff) << '.'
      << ((ip >> 16) & 0xff) << '.'
      << ((ip >>  8) & 0xff) << '.'
      << ((ip >>  0) & 0xff);
    return s.str();
}

int Utility::rand()
{
    static bool init = false;
    if (!init)
    {
        init = true;
        srand(time(NULL));
    }
    return ::rand();
}

uint32_t Utility::random32()
{
    uint32_t value = 0;
    int randomFd = open("/dev/urandom", O_RDONLY);
    if (randomFd != -1)
    {
        ssize_t length = read(randomFd, &value, sizeof(value));
        close(randomFd);
        if (length == (ssize_t)sizeof(value) && value != 0)
            return value;
    }

    value = ((uint32_t)Utility::rand() << 16) ^
            (uint32_t)Utility::rand() ^ (uint32_t)getpid() ^
            (uint32_t)time(NULL);
    return value == 0 ? 1 : value;
}

void Utility::secureRandom(void *output, size_t length)
{
    unsigned char *data = static_cast<unsigned char *>(output);
    int randomFd = open("/dev/urandom", O_RDONLY);
    if (randomFd == -1)
        throw Exception("opening operating-system random source", true);
    size_t offset = 0;
    while (offset < length)
    {
        ssize_t count = read(randomFd, data + offset, length - offset);
        if (count > 0)
            offset += (size_t)count;
        else if (count < 0 && errno == EINTR)
            continue;
        else
        {
            int saved = errno;
            close(randomFd);
            errno = saved;
            throw Exception("reading operating-system random source", true);
        }
    }
    close(randomFd);
}

bool Utility::isDeviceId(const string &id)
{
    if (id.size() != DEVICE_ID_HEX_SIZE)
        return false;

    for (string::const_iterator it = id.begin(); it != id.end(); ++it)
    {
        if (!( (*it >= '0' && *it <= '9') ||
               (*it >= 'a' && *it <= 'f') ||
               (*it >= 'A' && *it <= 'F') ))
            return false;
    }
    return true;
}

string Utility::normalizeDeviceId(const string &id)
{
    if (!isDeviceId(id))
        throw Exception("device id must contain exactly 32 hexadecimal characters");

    string result = id;
    for (string::iterator it = result.begin(); it != result.end(); ++it)
    {
        if (*it >= 'A' && *it <= 'F')
            *it = *it - 'A' + 'a';
    }
    return result;
}

string Utility::defaultStateFile(const string &name)
{
    const char *overrideDir = getenv("HANS_STATE_DIR");
    if (overrideDir != NULL && overrideDir[0] != '\0')
        return string(overrideDir) + "/" + name;

#ifdef WIN32
    // Cygwin HOME can be unset or even "/" when hans.exe is launched from
    // PowerShell, OpenSSH, Task Scheduler, or a service. Native Windows state
    // belongs under LocalAppData and must not depend on a Cygwin installation.
    const char *windowsHome = getenv("LOCALAPPDATA");
    if (windowsHome == NULL || windowsHome[0] == '\0')
        windowsHome = getenv("USERPROFILE");
    if (windowsHome != NULL && windowsHome[0] != '\0')
    {
        string stateDir(windowsHome);
        for (string::iterator it = stateDir.begin(); it != stateDir.end(); ++it)
            if (*it == '\\') *it = '/';
        return stateDir + "/Hans/" + name;
    }
#endif

    if (geteuid() == 0)
        return string("/var/lib/hans/") + name;

    const char *home = getenv("HOME");
    if (home != NULL && home[0] != '\0')
        return string(home) + "/.hans/" + name;

    return string("/tmp/hans-") + name;
}

void Utility::ensureParentDirectory(const string &path)
{
    string::size_type slash = path.rfind('/');
    if (slash == string::npos || slash == 0)
        return;

    string parent = path.substr(0, slash);
    string::size_type position = 1;
    while ((position = parent.find('/', position)) != string::npos)
    {
        string component = parent.substr(0, position);
        if (mkdir(component.c_str(), 0755) == -1 && errno != EEXIST)
            throw Exception("could not create state directory", true);
        position++;
    }

    if (mkdir(parent.c_str(), 0700) == -1 && errno != EEXIST)
        throw Exception("could not create state directory", true);
}

string Utility::loadOrCreateDeviceId(const string &path)
{
    std::ifstream input(path.c_str());
    string id;
    if (input >> id)
        return normalizeDeviceId(id);

    Utility::ensureParentDirectory(path);

    unsigned char randomBytes[DEVICE_ID_HEX_SIZE / 2];
    int randomFd = open("/dev/urandom", O_RDONLY);
    bool haveRandom = false;
    if (randomFd != -1)
    {
        ssize_t length = read(randomFd, randomBytes, sizeof(randomBytes));
        close(randomFd);
        haveRandom = length == (ssize_t)sizeof(randomBytes);
    }

    if (!haveRandom)
    {
        for (unsigned int i = 0; i < sizeof(randomBytes); ++i)
            randomBytes[i] = (unsigned char)(Utility::rand() ^ getpid() ^ (i * 37));
    }

    std::ostringstream encoded;
    encoded << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < sizeof(randomBytes); ++i)
        encoded << std::setw(2) << (unsigned int)randomBytes[i];
    id = encoded.str();

    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd == -1)
    {
        if (errno == EEXIST)
        {
            std::ifstream racedInput(path.c_str());
            if (racedInput >> id)
                return normalizeDeviceId(id);
        }
        throw Exception("could not create device id file", true);
    }

    string contents = id + "\n";
    ssize_t written = write(fd, contents.data(), contents.size());
    int savedErrno = errno;
    close(fd);
    if (written != (ssize_t)contents.size())
    {
        errno = savedErrno;
        throw Exception("could not write device id file", true);
    }

    return id;
}
