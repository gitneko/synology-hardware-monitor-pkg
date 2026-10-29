/**
 * This is the CloudFlare Worker code that serves the package JSON
 * for the Synology Package Center.
 * Simply add the CF Worker URL plus the tag name as path as URL.
 */

const x64_arch = [
    "x86_64", // Meta arch
    "apollolake",
    "avoton",
    "braswell",
    "broadwell",
    "broadwellnk",
    "broadwellnkv2",
    "broadwellntbap",
    "bromolow",
    "cedarview",
    "denverton",
    "epyc7002",
    "epyc7003",
    "geminilake",
    "geminilakenk",
    "grantley",
    "icelaked",
    "kvmcloud",
    "kvmx64",
    "purley",
    "r1000",
    "r1000nk",
    "v1000",
    "v1000nk"
];

const GH_USERNAME = "";
const GH_REPONAME = "";

const api_releases_url = "https://api.github.com/repos/" + GH_USERNAME + "/" + GH_REPONAME + "/releases";
const api_headers = { "Accept": "application/vnd.github+json", "Authorization": null, "User-Agent": GH_USERNAME };

const data_cache_duration = 600000; // in ms
let releases_timestamp = 0;
let releases = {};
let latest_stable = { tag: null, timestamp: 0 };

export default {
    async fetch(request, env, ctx) {
        api_headers.Authorization = "token " + env.GITHUB_PUB_TOKEN;

        // 1. Instantiate the URL object with the incoming request URL
        const url = new URL(request.url);

        if (((new Date()).valueOf() - data_cache_duration) > releases_timestamp || url.searchParams.get("forceUpdate") === '1') {
            console.log('Do refresh data');

            const rel_resp = await fetch(api_releases_url, { method: "GET", headers: api_headers });
            if (!rel_resp.ok) {
                console.log('build_releases_data_fetch_fail', rel_resp.status);
                return new Response("build_releases_data_fetch_fail", {
                    status: 500,
                    statusText: "Internal Server Error",
                    headers: {
                        "Content-Type": "text/plain",
                    },
                });
            }

            const rel_data = await rel_resp.json();
            const data = {};

            // Re-compute from scratch, to make sure all releases here exist
            latest_stable = {tag: null, timestamp: 0};

            for (const release of rel_data) {
                console.log('release: ', release);

                let pkg_url;

                for (const asset of release.assets) {
                    console.log('asset: ', asset);

                    if (asset.name !== "build-manifest.json") {
                        if (asset.name.endsWith('.spk')) {
                            pkg_url = asset.browser_download_url;
                        }

                        continue;
                    }

                    const asset_response = await fetch(asset.browser_download_url);
                    if (!asset_response.ok) {
                        console.log('build_asset_data_fetch_fail', asset_response.status);
                        return new Response("build_asset_data_fetch_fail", {
                            status: 500,
                            statusText: "Internal Server Error",
                            headers: {
                                "Content-Type": "text/plain",
                            },
                        });
                    }

                    const asset_data = await asset_response.json();
                    if (
                        typeof asset_data.version !== "string" ||
                        typeof asset_data.packages_md5 !== "string" ||
                        !/^[0-9a-f]{32}$/i.test(asset_data.packages_md5) ||
                        !asset_data.packages_size ||
                        !Number.isSafeInteger(asset_data.packages_size) ||
                        asset_data.packages_size <= 0
                    ) {
                        console.log('build_asset_data_fetch_invalid', asset_data);
                        continue;
                    }

                    data[release.tag_name] = asset_data;
                    data[release.tag_name].prerelease = release.prerelease;
                }

                // Skip releases without both a manifest and an SPK
                if (!data[release.tag_name] || !pkg_url) {
                    delete data[release.tag_name];
                    continue;
                }

                data[release.tag_name].pkg_url = pkg_url;

                if (!release.prerelease && latest_stable.timestamp < (new Date(release.updated_at)).valueOf()) {
                    console.log('New latest release: ', release.tag_name, release.updated_at);

                    latest_stable.tag = release.tag_name;
                    latest_stable.timestamp = (new Date(release.updated_at)).valueOf();
                }
            }

            releases_timestamp = (new Date()).valueOf();
            releases = data;
        }

        let tag = url.pathname.substring(1);
        if (tag === '') {
            tag = latest_stable.tag;
        }

        if (tag === null || releases[tag] === undefined || releases[tag].version === undefined) {
            return new Response("invalid_tag", {
                status: 400,
                statusText: "Bad Request",
                headers: {
                    "Content-Type": "text/plain",
                },
            });
        }

        let continue_data = false;
        if (request.method === "GET") {
            // 2. Use searchParams.get() to extract the specific keys
            const arch = url.searchParams.get("arch");   // Returns "v1000"
            const major = url.searchParams.get("major"); // Returns "7"

            continue_data = (major === "7" && x64_arch.some(val => val === arch));
        }

        let packages;
        if (continue_data) {
            const data = releases[tag];

            packages = [
                {
                    "package": "HardwareMonitor",
                    "version": data.version,
                    "md5": data.packages_md5,
                    "size": data.packages_size,
                    "dname": "Hardware Monitor",
                    "desc": "Synology Hardware Monitor Package to monitor hosts with Redfish APIs & SNMP.",
                    "thirdparty": true,
                    "category": 0,
                    "subcategory": 0,
                    "type": 0,
                    "price": 0,
                    "download_count": 0,
                    "recent_download_count": 0,
                    "silent_install": false,
                    "silent_uninstall": false,
                    "silent_upgrade": false,
                    "auto_upgrade_from": false,
                    "qinst": true,
                    "qstart": true,
                    "qupgrade": true,
                    "depsers": null,
                    "deppkgs": null,
                    "conflictpkgs": null,
                    "start": true,
                    "maintainer": "Hardware Monitor contributors",
                    "maintainer_url": null,
                    "distributor": null,
                    "distributor_url": null,
                    "support_url": "https://github.com/" + GH_USERNAME + "/" + GH_REPONAME,
                    "changelog": "",
                    "beta": data.prerelease,
                    "link": data.pkg_url,
                    "icon_120": "https://raw.githubusercontent.com/" + GH_USERNAME + "/" + GH_REPONAME + "/e23fa3a9db1fc4d39e62f7f885898bd0e66b26e7/packaging/ui/images/icon.svg",
                    "thumbnail": "https://raw.githubusercontent.com/" + GH_USERNAME + "/" + GH_REPONAME + "/master/docs/images/devices-en.jpg",
                    "snapshot": [],
                }
            ];
        } else {
            packages = [];
        }

        return new Response(JSON.stringify(packages), {
            headers: { "Content-Type": "application/json" },
        });
    },
};
