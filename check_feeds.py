#!/usr/bin/env python3
"""
Feed URL Validator - Check which threat intelligence feeds are still alive
"""

import requests
import time
from urllib.parse import urlparse

def check_url(url, timeout=10):
    """Check if a URL is accessible and return status info"""
    if not url.strip():
        return None

    try:
        # Set a reasonable user-agent
        headers = {
            'User-Agent': 'Combine-FeedValidator/2.0 (https://github.com/mlsecproject/combine)'
        }

        response = requests.head(url, timeout=timeout, headers=headers, allow_redirects=True)

        # If HEAD doesn't work, try GET
        if response.status_code == 405 or response.status_code >= 500:
            response = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True, stream=True)
            # Only read first 1KB to check if it's accessible
            next(response.iter_content(1024), None)

        return {
            'url': url,
            'status': response.status_code,
            'accessible': response.status_code == 200,
            'redirected': response.url != url if hasattr(response, 'url') else False,
            'final_url': response.url if hasattr(response, 'url') else url,
            'error': None
        }
    except requests.exceptions.SSLError as e:
        return {
            'url': url,
            'status': None,
            'accessible': False,
            'redirected': False,
            'final_url': url,
            'error': f'SSL Error: {str(e)[:100]}'
        }
    except requests.exceptions.Timeout:
        return {
            'url': url,
            'status': None,
            'accessible': False,
            'redirected': False,
            'final_url': url,
            'error': 'Timeout'
        }
    except requests.exceptions.ConnectionError as e:
        return {
            'url': url,
            'status': None,
            'accessible': False,
            'redirected': False,
            'final_url': url,
            'error': f'Connection Error: {str(e)[:100]}'
        }
    except Exception as e:
        return {
            'url': url,
            'status': None,
            'accessible': False,
            'redirected': False,
            'final_url': url,
            'error': f'{type(e).__name__}: {str(e)[:100]}'
        }

def read_urls_from_file(filename):
    """Read URLs from a text file, one per line"""
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def main():
    print("=" * 80)
    print("COMBINE FEED URL VALIDATION REPORT")
    print("=" * 80)
    print()

    # Check inbound feeds
    print("🔍 INBOUND FEEDS (Defensive - Scanners, Brute Force, etc.)")
    print("-" * 80)
    inbound_urls = read_urls_from_file('inbound_urls.txt')
    inbound_results = []

    for i, url in enumerate(inbound_urls, 1):
        print(f"[{i}/{len(inbound_urls)}] Checking {url[:60]}...", end=' ', flush=True)
        result = check_url(url)
        inbound_results.append(result)

        if result['accessible']:
            print("✅ OK")
        else:
            error_msg = result['error'] or f"HTTP {result['status']}"
            print(f"❌ FAILED - {error_msg}")

        # Be nice to servers
        time.sleep(0.5)

    print()
    print("🔍 OUTBOUND FEEDS (Offensive - Malware, C&C, Exploit Kits)")
    print("-" * 80)
    outbound_urls = read_urls_from_file('outbound_urls.txt')
    outbound_results = []

    for i, url in enumerate(outbound_urls, 1):
        print(f"[{i}/{len(outbound_urls)}] Checking {url[:60]}...", end=' ', flush=True)
        result = check_url(url)
        outbound_results.append(result)

        if result['accessible']:
            print("✅ OK")
        else:
            error_msg = result['error'] or f"HTTP {result['status']}"
            print(f"❌ FAILED - {error_msg}")

        time.sleep(0.5)

    # Summary
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)

    inbound_alive = sum(1 for r in inbound_results if r['accessible'])
    outbound_alive = sum(1 for r in outbound_results if r['accessible'])
    total_alive = inbound_alive + outbound_alive
    total_feeds = len(inbound_results) + len(outbound_results)

    print(f"\n📊 Overall Status:")
    print(f"   Total Feeds: {total_feeds}")
    print(f"   ✅ Alive: {total_alive} ({total_alive/total_feeds*100:.1f}%)")
    print(f"   ❌ Dead: {total_feeds - total_alive} ({(total_feeds-total_alive)/total_feeds*100:.1f}%)")
    print()
    print(f"   Inbound: {inbound_alive}/{len(inbound_results)} alive ({inbound_alive/len(inbound_results)*100:.1f}%)")
    print(f"   Outbound: {outbound_alive}/{len(outbound_results)} alive ({outbound_alive/len(outbound_results)*100:.1f}%)")

    # Dead feeds detail
    print(f"\n❌ DEAD FEEDS ({total_feeds - total_alive}):")
    print("-" * 80)

    all_results = [('INBOUND', r) for r in inbound_results] + [('OUTBOUND', r) for r in outbound_results]
    dead_feeds = [(feed_type, r) for feed_type, r in all_results if not r['accessible']]

    if dead_feeds:
        for feed_type, result in dead_feeds:
            error_msg = result['error'] or f"HTTP {result['status']}"
            print(f"[{feed_type}] {result['url']}")
            print(f"         Error: {error_msg}")
            print()
    else:
        print("   None! All feeds are accessible! 🎉")

    print()
    print("=" * 80)

if __name__ == '__main__':
    main()
