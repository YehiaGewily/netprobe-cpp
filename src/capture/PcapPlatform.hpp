#pragma once

#ifdef _WIN32
#ifndef HAVE_REMOTE
#define HAVE_REMOTE
#endif
#include <pcap.h>
#else
#if __has_include(<pcap/pcap.h>)
#include <pcap/pcap.h>
#else
#include <pcap.h>
#endif
#endif
