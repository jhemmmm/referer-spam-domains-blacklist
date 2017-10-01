#!/usr/bin/env python3

""" Remove dead domains from list. """

import argparse
import asyncio
import collections
import errno
import random
import resource

import aiodns
import tqdm


DNS_SERVERS = ("8.8.8.8",  # Google DNS
               "208.67.222.222",  # OpenDNS
               "84.200.69.80",  # DNS.WATCH
               "209.244.0.3",  # Level3 DNS
               "8.26.56.26")  # Comodo Secure DNS
WEB_PORTS = (80, 443)
MAX_CONCURRENT_REQUESTS_PER_DNS_SERVER = 8


async def dns_resolve(domain, dns_server, sem, async_loop):
  """ Return IP string if domain has a DNA A record on this DNS server, False otherwise. """
  resolver = aiodns.DNSResolver(nameservers=(dns_server,), loop=async_loop)
  timeout = 0.5
  for attempt in range(1, 20 + 1):
    coroutine = resolver.query(domain, "A")
    try:
      with (await sem):
        response = await asyncio.wait_for(coroutine, timeout=timeout, loop=async_loop)
    except asyncio.TimeoutError:
      jitter = random.randint(-20, 20) / 100
      timeout = min(timeout * 1.5, 5) + jitter
      continue
    except aiodns.error.DNSError:
      return False
    else:
      ip = response[0].host
      break
  else:
    # too many failed attemps
    return False
  return ip


async def dns_resolve_domain(domain, progress, sems, async_loop):
  """ Return IP string if domain has a DNA A record on this DNS server, False otherwise. """
  dns_servers = list(DNS_SERVERS)
  random.shuffle(dns_servers)
  r = []
  for dns_server in dns_servers:
    ip = await dns_resolve(domain, dns_server, sems[dns_server], async_loop)
    r.append(ip or None)
  progress.update(1)
  if progress.n == progress.total:
    async_loop.stop()
  return r


async def has_tcp_port_open(ip, port, progress, async_loop):
  """ Return True if domain is listening on a TCP port, False instead. """
  r = True
  coroutine = asyncio.open_connection(ip, port)
  try:
    await asyncio.wait_for(coroutine, timeout=10)
  except (ConnectionRefusedError, asyncio.TimeoutError):
    r = False
  except OSError as e:
    if e.errno == errno.EHOSTUNREACH:
      r = False
    else:
      raise
  progress.update(1)
  if progress.n == progress.total:
    async_loop.stop()
  return r


if __name__ == "__main__":
  # parse args
  arg_parser = argparse.ArgumentParser(description=__doc__,
                                       formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  arg_parser.add_argument("list_file",
                          help="Domain list file path")
  args = arg_parser.parse_args()

  # read list
  with open(args.list_file, "rt") as list_file:
    domains = tuple(map(str.rstrip, list_file.readlines()))
  dead_domains = set()

  # bump limits
  soft_lim, hard_lim = resource.getrlimit(resource.RLIMIT_NOFILE)
  if ((soft_lim != resource.RLIM_INFINITY) and
          ((soft_lim < hard_lim) or (hard_lim == resource.RLIM_INFINITY))):
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard_lim, hard_lim))
    print("Max open files count set from %u to %u" % (soft_lim, hard_lim))

  # resolve domains
  async_loop = asyncio.get_event_loop()
  sems = collections.defaultdict(lambda: asyncio.BoundedSemaphore(MAX_CONCURRENT_REQUESTS_PER_DNS_SERVER,
                                                                  loop=async_loop))
  dns_check_futures = []
  tcp_check_domain_ips = {}
  with tqdm.tqdm(total=len(domains),
                 miniters=1,
                 smoothing=0,
                 desc="Domains checks",
                 unit=" domains") as progress:
    for domain in domains:
      coroutine = dns_resolve_domain(domain, progress, sems, async_loop)
      future = asyncio.ensure_future(coroutine, loop=async_loop)
      dns_check_futures.append(future)

    async_loop.run_forever()

    for domain, future in zip(domains, dns_check_futures):
      ips = future.result()
      if not any(ips):
        # all dns resolutions failed for this domain
        dead_domains.add(domain)
      elif not all(ips):
        # at least one dns resolution failed, but at least one succeeded for this domain
        tcp_check_domain_ips[domain] = ips

  # for domains with at least one failed DNS resolution, check open ports
  tcp_check_futures = collections.defaultdict(list)
  with tqdm.tqdm(total=len(tcp_check_domain_ips) * len(WEB_PORTS),
                 miniters=1,
                 desc="TCP domain checks",
                 unit=" domains",
                 leave=True) as progress:
    for domain, ips in tcp_check_domain_ips.items():
      ip = next(filter(None, ips))  # take result of first successful resolution
      for port in WEB_PORTS:
        coroutine = has_tcp_port_open(ip, port, progress, async_loop)
        future = asyncio.ensure_future(coroutine, loop=async_loop)
        tcp_check_futures[domain].append(future)

    async_loop.run_forever()

    for domain, futures in tcp_check_futures.items():
      status = tuple(future.result() for future in futures)
      if not any(status):
        # no web port open for this domain
        dead_domains.add(domain)

  # write new file
  with open(args.list_file, "wt") as list_file:
    for domain in domains:
      if domain not in dead_domains:
        list_file.write("%s\n" % (domain))
  print("\n%u dead domain(s) removed" % (len(dead_domains)))
