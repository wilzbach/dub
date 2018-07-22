module dub.packagesuppliers.git;

import dub.packagesuppliers.packagesupplier;

package enum PackagesPath = "packages";

/**
	Git based package supplier.

	This package supplier downloads git packages.
*/
class GitPackageSupplier : PackageSupplier {
	import dub.internal.utils : download, HTTPStatusException;
	import dub.internal.vibecompat.core.log;
	import dub.internal.vibecompat.data.json : parseJson, parseJsonString, serializeToJson;
	import dub.internal.vibecompat.inet.url : URL;

	//import std.datetime : Clock, Duration, hours, SysTime, UTC;
	//private {
		//URL m_registryUrl;
		//struct CacheEntry { Json data; SysTime cacheTime; }
		//CacheEntry[string] m_metadataCache;
		//Duration m_maxCacheTime;
	//}

 	this()
	{
		//m_registryUrl = registry;
	}

	override @property string description() { return "git"; }

	Version[] getVersions(string package_id)
	{
		logInfo("git::getVersions");
		return null;
	}

	void fetchPackage(NativePath path, string packageId, Dependency dep, bool pre_release)
	{
		//import std.array : replace;
		//import std.format : format;
		//auto md = getMetadata(packageId);
		//Json best = getBestPackage(md, packageId, dep, pre_release);
		//if (best.type == Json.Type.null_)
			//return;
		//auto vers = best["version"].get!string;
		//auto url = m_registryUrl ~ NativePath(PackagesPath~"/"~packageId~"/"~vers~".zip");
		//logDiagnostic("Downloading from '%s'", url);
		//foreach(i; 0..3) {
			//try{
				//download(url, path);
				//return;
			//}
			//catch(HTTPStatusException e) {
				//if (e.status == 404) throw e;
				//else {
					//logDebug("Failed to download package %s from %s (Attempt %s of 3)", packageId, url, i + 1);
					//continue;
				//}
			//}
		//}
		//throw new Exception("Failed to download package %s from %s".format(packageId, url));
		import std.process;
		logInfo("Fetch package: %s", packageId);
		import std.stdio;
		executeShell("git clone --depth 1 git@github.com/dlang/dub.git " ~ path.toString).writeln;
		logInfo("Removing");
		//execute(["rm", "-r", (path ~ ".git").toString]);
	}

	Json fetchPackageRecipe(string packageId, Dependency dep, bool pre_release)
	{
		logInfo("git::fetchPackageRecipe");
		//auto md = getMetadata(packageId);
		//return getBestPackage(md, packageId, dep, pre_release);
		throw new Exception("foo");
		//Json json;
		//json["name"] = packageId;
		//json["version"] = "0.0.0";
		//return json;
	}

	private Json getMetadata(string packageId)
	{
		logInfo("git::getMetadata");
		// TODO!
		return Json();
	}

	SearchResult[] searchPackages(string query) {
		logInfo("git::searchPackages");
		// TODO!
		return null;
	}
}

