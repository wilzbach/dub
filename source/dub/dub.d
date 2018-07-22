/**
	A package manager.

	Copyright: © 2012-2013 Matthias Dondorff, 2012-2016 Sönke Ludwig
	License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
	Authors: Matthias Dondorff, Sönke Ludwig
*/
module dub.dub;

import dub.compilers.compiler;
import dub.dependency;
import dub.dependencyresolver;
import dub.internal.utils;
import dub.internal.vibecompat.core.file;
import dub.internal.vibecompat.core.log;
import dub.internal.vibecompat.data.json;
import dub.internal.vibecompat.inet.url;
import dub.package_;
import dub.packagemanager;
import dub.packagesuppliers;
import dub.project;
import dub.generators.generator;
import dub.init;

import std.algorithm;
import std.array : array, replace;
import std.conv : to;
import std.exception : enforce;
import std.file;
import std.process : environment;
import std.range : empty;
import std.string;
import std.encoding : sanitize;

// Workaround for libcurl liker errors when building with LDC
version (LDC) pragma(lib, "curl");

// Set output path and options for coverage reports
version (DigitalMars) version (D_Coverage) static if (__VERSION__ >= 2068)
{
	shared static this()
	{
		import core.runtime, std.file, std.path, std.stdio;
		dmd_coverSetMerge(true);
		auto path = buildPath(dirName(thisExePath()), "../cov");
		if (!path.exists)
			mkdir(path);
		dmd_coverDestPath(path);
	}
}

static this()
{
	import dub.compilers.dmd : DMDCompiler;
	import dub.compilers.gdc : GDCCompiler;
	import dub.compilers.ldc : LDCCompiler;
	registerCompiler(new DMDCompiler);
	registerCompiler(new GDCCompiler);
	registerCompiler(new LDCCompiler);
}

/// The URL to the official package registry.
enum defaultRegistryURL = "https://code.dlang.org/";
enum fallbackRegistryURLs = [
	// fallback in case of HTTPS problems
	"http://code.dlang.org/",
	"https://code-mirror.dlang.io/",
	"https://code-mirror2.dlang.io/",
	"https://dub-registry.herokuapp.com/",
];

/** Returns a default list of package suppliers.

	This will contain a single package supplier that points to the official
	package registry.

	See_Also: `defaultRegistryURL`
*/
PackageSupplier[] defaultPackageSuppliers()
{
	logDiagnostic("Using dub registry url '%s'", defaultRegistryURL);
	return [
		//cast(PackageSupplier) new GitPackageSupplier(),
		new FallbackPackageSupplier(
			new RegistryPackageSupplier(URL(defaultRegistryURL)),
			fallbackRegistryURLs.map!(x => cast(PackageSupplier) new RegistryPackageSupplier(URL(x))).array
		)
	];
}

/** Returns a registry package supplier according to protocol.

	Allowed protocols are dub+http(s):// and maven+http(s)://.
*/
PackageSupplier getRegistryPackageSupplier(string url)
{
	switch (url.startsWith("dub+", "mvn+"))
	{
		case 1:
			return new RegistryPackageSupplier(URL(url[4..$]));
		case 2:
			return new MavenRegistryPackageSupplier(URL(url[4..$]));
		default:
			return new RegistryPackageSupplier(URL(url));
	}
}

unittest
{
	auto dubRegistryPackageSupplier = getRegistryPackageSupplier("dub+https://code.dlang.org");
	assert(dubRegistryPackageSupplier.description.canFind(" https://code.dlang.org"));

	dubRegistryPackageSupplier = getRegistryPackageSupplier("https://code.dlang.org");
	assert(dubRegistryPackageSupplier.description.canFind(" https://code.dlang.org"));

	auto mavenRegistryPackageSupplier = getRegistryPackageSupplier("mvn+http://localhost:8040/maven/libs-release/dubpackages");
	assert(mavenRegistryPackageSupplier.description.canFind(" http://localhost:8040/maven/libs-release/dubpackages"));
}

/** Provides a high-level entry point for DUB's functionality.

	This class provides means to load a certain project (a root package with
	all of its dependencies) and to perform high-level operations as found in
	the command line interface.
*/
class Dub {
	private {
		bool m_dryRun = false;
		PackageManager m_packageManager;
		PackageSupplier[] m_packageSuppliers;
		NativePath m_rootPath;
		SpecialDirs m_dirs;
		DubConfig m_config;
		NativePath m_projectPath;
		Project m_project;
		NativePath m_overrideSearchPath;
		string m_defaultCompiler;
		string m_defaultArchitecture;
	}

	/** The default placement location of fetched packages.

		This property can be altered, so that packages which are downloaded as part
		of the normal upgrade process are stored in a certain location. This is
		how the "--local" and "--system" command line switches operate.
	*/
	PlacementLocation defaultPlacementLocation = PlacementLocation.user;


	/** Initializes the instance for use with a specific root package.

		Note that a package still has to be loaded using one of the
		`loadPackage` overloads.

		Params:
			root_path = Path to the root package
			additional_package_suppliers = A list of package suppliers to try
				before the suppliers found in the configurations files and the
				`defaultPackageSuppliers`.
			skip_registry = Can be used to skip using the configured package
				suppliers, as well as the default suppliers.
	*/
	this(string root_path = ".", PackageSupplier[] additional_package_suppliers = null,
			SkipPackageSuppliers skip_registry = SkipPackageSuppliers.none)
	{
		m_rootPath = NativePath(root_path);
		if (!m_rootPath.absolute) m_rootPath = NativePath(getcwd()) ~ m_rootPath;

		init();

		if (skip_registry == SkipPackageSuppliers.none)
			m_packageSuppliers = getPackageSuppliers(additional_package_suppliers);
		else
			m_packageSuppliers = getPackageSuppliers(additional_package_suppliers, skip_registry);

		m_packageManager = new PackageManager(m_dirs.localRepository, m_dirs.systemSettings);

		auto ccps = m_config.customCachePaths;
		if (ccps.length)
			m_packageManager.customCachePaths = ccps;

		updatePackageSearchPath();
	}

	unittest
	{
		scope (exit) environment.remove("DUB_REGISTRY");
		auto dub = new Dub(".", null, SkipPackageSuppliers.configured);
		assert(dub.m_packageSuppliers.length == 0);
		environment["DUB_REGISTRY"] = "http://example.com/";
		dub = new Dub(".", null, SkipPackageSuppliers.configured);
		assert(dub.m_packageSuppliers.length == 1);
		environment["DUB_REGISTRY"] = "http://example.com/;http://foo.com/";
		dub = new Dub(".", null, SkipPackageSuppliers.configured);
		assert(dub.m_packageSuppliers.length == 2);
		dub = new Dub(".", [new RegistryPackageSupplier(URL("http://bar.com/"))], SkipPackageSuppliers.configured);
		assert(dub.m_packageSuppliers.length == 3);
	}

	/** Get the list of package suppliers.

		Params:
			additional_package_suppliers = A list of package suppliers to try
				before the suppliers found in the configurations files and the
				`defaultPackageSuppliers`.
			skip_registry = Can be used to skip using the configured package
				suppliers, as well as the default suppliers.
	*/
	public PackageSupplier[] getPackageSuppliers(PackageSupplier[] additional_package_suppliers, SkipPackageSuppliers skip_registry)
	{
		PackageSupplier[] ps = additional_package_suppliers;

		if (skip_registry < SkipPackageSuppliers.all)
		{
			ps ~= environment.get("DUB_REGISTRY", null)
				.splitter(";")
				.map!(url => getRegistryPackageSupplier(url))
				.array;
		}

		if (skip_registry < SkipPackageSuppliers.configured)
		{
			ps ~= m_config.registryURLs
				.map!(url => getRegistryPackageSupplier(url))
				.array;
		}

		if (skip_registry < SkipPackageSuppliers.standard)
			ps ~= defaultPackageSuppliers();

		return ps;
	}

	/// ditto
	public PackageSupplier[] getPackageSuppliers(PackageSupplier[] additional_package_suppliers)
	{
		return getPackageSuppliers(additional_package_suppliers, m_config.skipRegistry);
	}

	unittest
	{
		scope (exit) environment.remove("DUB_REGISTRY");
		auto dub = new Dub(".", null, SkipPackageSuppliers.none);

		dub.m_config = new DubConfig(Json(["skipRegistry": Json("none")]), null);
		assert(dub.getPackageSuppliers(null).length == 1);

		dub.m_config = new DubConfig(Json(["skipRegistry": Json("configured")]), null);
		assert(dub.getPackageSuppliers(null).length == 0);

		dub.m_config = new DubConfig(Json(["skipRegistry": Json("standard")]), null);
		assert(dub.getPackageSuppliers(null).length == 0);

		environment["DUB_REGISTRY"] = "http://example.com/";
		assert(dub.getPackageSuppliers(null).length == 1);
	}

	/** Initializes the instance with a single package search path, without
		loading a package.

		This constructor corresponds to the "--bare" option of the command line
		interface. Use
	*/
	this(NativePath override_path)
	{
		init();
		m_overrideSearchPath = override_path;
		m_packageManager = new PackageManager(NativePath(), NativePath(), false);
		updatePackageSearchPath();
	}

	private void init()
	{
		import std.file : tempDir;
		version(Windows) {
			m_dirs.systemSettings = NativePath(environment.get("ProgramData")) ~ "dub/";
			immutable appDataDir = environment.get("APPDATA");
			m_dirs.userSettings = NativePath(appDataDir) ~ "dub/";
			m_dirs.localRepository = NativePath(environment.get("LOCALAPPDATA", appDataDir)) ~ "dub";

			migrateRepositoryFromRoaming(m_dirs.userSettings ~"\\packages", m_dirs.localRepository ~ "\\packages");

		} else version(Posix){
			m_dirs.systemSettings = NativePath("/var/lib/dub/");
			m_dirs.userSettings = NativePath(environment.get("HOME")) ~ ".dub/";
			if (!m_dirs.userSettings.absolute)
				m_dirs.userSettings = NativePath(getcwd()) ~ m_dirs.userSettings;
			m_dirs.localRepository = m_dirs.userSettings;
		}

		m_dirs.temp = NativePath(tempDir);

		m_config = new DubConfig(jsonFromFile(m_dirs.systemSettings ~ "settings.json", true), m_config);
		m_config = new DubConfig(jsonFromFile(NativePath(thisExePath).parentPath ~ "../etc/dub/settings.json", true), m_config);
		m_config = new DubConfig(jsonFromFile(m_dirs.userSettings ~ "settings.json", true), m_config);

		determineDefaultCompiler();

		m_defaultArchitecture = m_config.defaultArchitecture;
	}

	version(Windows)
	private void migrateRepositoryFromRoaming(NativePath roamingDir, NativePath localDir)
	{
        immutable roamingDirPath = roamingDir.toNativeString();
	    if (!existsDirectory(roamingDir)) return;

        immutable localDirPath = localDir.toNativeString();
        logInfo("Detected a package cache in " ~ roamingDirPath ~ ". This will be migrated to " ~ localDirPath ~ ". Please wait...");
        if (!existsDirectory(localDir))
        {
            mkdirRecurse(localDirPath);
        }

        runCommand("xcopy /s /e /y " ~ roamingDirPath ~ " " ~ localDirPath ~ " > NUL");
        rmdirRecurse(roamingDirPath);
	}


	@property void dryRun(bool v) { m_dryRun = v; }

	/** Returns the root path (usually the current working directory).
	*/
	@property NativePath rootPath() const { return m_rootPath; }
	/// ditto
	@property void rootPath(NativePath root_path)
	{
		m_rootPath = root_path;
		if (!m_rootPath.absolute) m_rootPath = NativePath(getcwd()) ~ m_rootPath;
	}

	/// Returns the name listed in the dub.json of the current
	/// application.
	@property string projectName() const { return m_project.name; }

	@property NativePath projectPath() const { return m_projectPath; }

	@property string[] configurations() const { return m_project.configurations; }

	@property inout(PackageManager) packageManager() inout { return m_packageManager; }

	@property inout(Project) project() inout { return m_project; }

	/** Returns the default compiler binary to use for building D code.

		If set, the "defaultCompiler" field of the DUB user or system
		configuration file will be used. Otherwise the PATH environment variable
		will be searched for files named "dmd", "gdc", "gdmd", "ldc2", "ldmd2"
		(in that order, taking into account operating system specific file
		extensions) and the first match is returned. If no match is found, "dmd"
		will be used.
	*/
	@property string defaultCompiler() const { return m_defaultCompiler; }

	/** Returns the default architecture to use for building D code.

		If set, the "defaultArchitecture" field of the DUB user or system
		configuration file will be used. Otherwise null will be returned.
	*/
	@property string defaultArchitecture() const { return m_defaultArchitecture; }

	/** Loads the package that resides within the configured `rootPath`.
	*/
	void loadPackage()
	{
		loadPackage(m_rootPath);
	}

	/// Loads the package from the specified path as the main project package.
	void loadPackage(NativePath path)
	{
		m_projectPath = path;
		updatePackageSearchPath();
		m_project = new Project(m_packageManager, m_projectPath);
	}

	/// Loads a specific package as the main project package (can be a sub package)
	void loadPackage(Package pack)
	{
		m_projectPath = pack.path;
		updatePackageSearchPath();
		m_project = new Project(m_packageManager, pack);
	}

	/** Loads a single file package.

		Single-file packages are D files that contain a package receipe comment
		at their top. A recipe comment must be a nested `/+ ... +/` style
		comment, containing the virtual recipe file name and a colon, followed by the
		recipe contents (what would normally be in dub.sdl/dub.json).

		Example:
		---
		/+ dub.sdl:
		   name "test"
		   dependency "vibe-d" version="~>0.7.29"
		+/
		import vibe.http.server;

		void main()
		{
			auto settings = new HTTPServerSettings;
			settings.port = 8080;
			listenHTTP(settings, &hello);
		}

		void hello(HTTPServerRequest req, HTTPServerResponse res)
		{
			res.writeBody("Hello, World!");
		}
		---

		The script above can be invoked with "dub --single test.d".
	*/
	void loadSingleFilePackage(NativePath path)
	{
		import dub.recipe.io : parsePackageRecipe;
		import std.file : mkdirRecurse, readText;
		import std.path : baseName, stripExtension;

		path = makeAbsolute(path);

		string file_content = readText(path.toNativeString());

		if (file_content.startsWith("#!")) {
			auto idx = file_content.indexOf('\n');
			enforce(idx > 0, "The source fine doesn't contain anything but a shebang line.");
			file_content = file_content[idx+1 .. $];
		}

		file_content = file_content.strip();

		string recipe_content;

		if (file_content.startsWith("/+")) {
			file_content = file_content[2 .. $];
			auto idx = file_content.indexOf("+/");
			enforce(idx >= 0, "Missing \"+/\" to close comment.");
			recipe_content = file_content[0 .. idx].strip();
		} else throw new Exception("The source file must start with a recipe comment.");

		auto nidx = recipe_content.indexOf('\n');

		auto idx = recipe_content.indexOf(':');
		enforce(idx > 0 && (nidx < 0 || nidx > idx),
			"The first line of the recipe comment must list the recipe file name followed by a colon (e.g. \"/+ dub.sdl:\").");
		auto recipe_filename = recipe_content[0 .. idx];
		recipe_content = recipe_content[idx+1 .. $];
		auto recipe_default_package_name = path.toString.baseName.stripExtension.strip;

		auto recipe = parsePackageRecipe(recipe_content, recipe_filename, null, recipe_default_package_name);
		enforce(recipe.buildSettings.sourceFiles.length == 0, "Single-file packages are not allowed to specify source files.");
		enforce(recipe.buildSettings.sourcePaths.length == 0, "Single-file packages are not allowed to specify source paths.");
		enforce(recipe.buildSettings.importPaths.length == 0, "Single-file packages are not allowed to specify import paths.");
		recipe.buildSettings.sourceFiles[""] = [path.toNativeString()];
		recipe.buildSettings.sourcePaths[""] = [];
		recipe.buildSettings.importPaths[""] = [];
		recipe.buildSettings.mainSourceFile = path.toNativeString();
		if (recipe.buildSettings.targetType == TargetType.autodetect)
			recipe.buildSettings.targetType = TargetType.executable;

		auto pack = new Package(recipe, path.parentPath, null, "~master");
		loadPackage(pack);
	}
	/// ditto
	void loadSingleFilePackage(string path)
	{
		loadSingleFilePackage(NativePath(path));
	}

	/** Disables the default search paths and only searches a specific directory
		for packages.
	*/
	void overrideSearchPath(NativePath path)
	{
		if (!path.absolute) path = NativePath(getcwd()) ~ path;
		m_overrideSearchPath = path;
		updatePackageSearchPath();
	}

	/** Gets the default configuration for a particular build platform.

		This forwards to `Project.getDefaultConfiguration` and requires a
		project to be loaded.
	*/
	string getDefaultConfiguration(BuildPlatform platform, bool allow_non_library_configs = true) const { return m_project.getDefaultConfiguration(platform, allow_non_library_configs); }

	/** Attempts to upgrade the dependency selection of the loaded project.

		Params:
			options = Flags that control how the upgrade is carried out
			packages_to_upgrade = Optional list of packages. If this list
				contains one or more packages, only those packages will
				be upgraded. Otherwise, all packages will be upgraded at
				once.
	*/
	void upgrade(UpgradeOptions options, string[] packages_to_upgrade = null)
	{
		logInfo("UPGRADE: %s", packages_to_upgrade);
		// clear non-existent version selections
		if (!(options & UpgradeOptions.upgrade)) {
			next_pack:
			foreach (p; m_project.selections.selectedPackages) {
				auto dep = m_project.selections.getSelectedVersion(p);
				if (!dep.path.empty) {
					auto path = dep.path;
					if (!path.absolute) path = this.rootPath ~ path;
					try if (m_packageManager.getOrLoadPackage(path)) continue;
					catch (Exception e) { logDebug("Failed to load path based selection: %s", e.toString().sanitize); }
				} else if (!dep.url.empty) {
					logInfo("Trying to select URL: %s", dep.url);
				} else {
					if (m_packageManager.getPackage(p, dep.version_)) continue;
					foreach (ps; m_packageSuppliers) {
						try {
							auto versions = ps.getVersions(p);
							if (versions.canFind!(v => dep.matches(v)))
								continue next_pack;
						} catch (Exception e) {
							logWarn("Error querying versions for %s, %s: %s", p, ps.description, e.msg);
							logDebug("Full error: %s", e.toString().sanitize());
						}
					}
				}

				logWarn("Selected package %s %s doesn't exist. Using latest matching version instead.", p, dep);
				m_project.selections.deselectVersion(p);
			}
		}

		Dependency[string] versions;
		auto resolver = new DependencyVersionResolver(this, options);
		foreach (p; packages_to_upgrade)
			resolver.addPackageToUpgrade(p);

		logInfo("RESOLVER START");
		versions = resolver.resolve(m_project.rootPackage, m_project.selections);
		logInfo("RESOLVER END");

		if (options & UpgradeOptions.dryRun) {
			bool any = false;
			string rootbasename = getBasePackageName(m_project.rootPackage.name);

			foreach (p, ver; versions) {
				if (!ver.path.empty) continue;

				auto basename = getBasePackageName(p);
				if (basename == rootbasename) continue;

				if (!m_project.selections.hasSelectedVersion(basename)) {
					logInfo("Package %s would be selected with version %s.",
						basename, ver);
					any = true;
					continue;
				}
				auto sver = m_project.selections.getSelectedVersion(basename);
				if (!sver.path.empty) continue;
				if (ver.version_ <= sver.version_) continue;
				logInfo("Package %s would be upgraded from %s to %s.",
					basename, sver, ver);
				any = true;
			}
			if (any) logInfo("Use \"dub upgrade\" to perform those changes.");
			return;
		}

		foreach (p; versions.byKey) {
			auto ver = versions[p]; // Workaround for DMD 2.070.0 AA issue (crashes in aaApply2 if iterating by key+value)
			assert(!p.canFind(":"), "Resolved packages contain a sub package!?: "~p);
			logInfo("UPGRADING: %s", p);
			Package pack;
			if (!ver.path.empty) {
				try pack = m_packageManager.getOrLoadPackage(ver.path);
				catch (Exception e) {
					logDebug("Failed to load path based selection: %s", e.toString().sanitize);
					continue;
				}
			} else if (!ver.url.empty) {
				// TODO: clone the git dependency
				// TODO: save git commit hash in the dub.selections.json
				logInfo("ver.url dependency");
				continue;
			} else {
				pack = m_packageManager.getBestPackage(p, ver);
				if (pack && m_packageManager.isManagedPackage(pack)
					&& ver.version_.isBranch && (options & UpgradeOptions.upgrade) != 0)
				{
					// TODO: only re-install if there is actually a new commit available
					logInfo("Re-installing branch based dependency %s %s", p, ver.toString());
					m_packageManager.remove(pack);
					pack = null;
				}
			}

			FetchOptions fetchOpts;
			fetchOpts |= (options & UpgradeOptions.preRelease) != 0 ? FetchOptions.usePrerelease : FetchOptions.none;
			if (!pack) fetch(p, ver, defaultPlacementLocation, fetchOpts, "getting selected version");
			if ((options & UpgradeOptions.select) && p != m_project.rootPackage.name) {
				if (ver.path.empty) m_project.selections.selectVersion(p, ver.version_);
				else {
					NativePath relpath = ver.path;
					if (relpath.absolute) relpath = relpath.relativeTo(m_project.rootPackage.path);
					m_project.selections.selectVersion(p, relpath);
				}
			}
		}

		m_project.reinit();

		if ((options & UpgradeOptions.select) && !(options & (UpgradeOptions.noSaveSelections | UpgradeOptions.dryRun)))
			m_project.saveSelections();
	}

	/** Generate project files for a specified generator.

		Any existing project files will be overridden.
	*/
	void generateProject(string ide, GeneratorSettings settings)
	{
		auto generator = createProjectGenerator(ide, m_project);
		if (m_dryRun) return; // TODO: pass m_dryRun to the generator
		generator.generate(settings);
	}

	/** Executes tests on the current project.

		Throws an exception, if unittests failed.
	*/
	void testProject(GeneratorSettings settings, string config, NativePath custom_main_file)
	{
		if (!custom_main_file.empty && !custom_main_file.absolute) custom_main_file = getWorkingDirectory() ~ custom_main_file;

		if (config.length == 0) {
			// if a custom main file was given, favor the first library configuration, so that it can be applied
			if (!custom_main_file.empty) config = m_project.getDefaultConfiguration(settings.platform, false);
			// else look for a "unittest" configuration
			if (!config.length && m_project.rootPackage.configurations.canFind("unittest")) config = "unittest";
			// if not found, fall back to the first "library" configuration
			if (!config.length) config = m_project.getDefaultConfiguration(settings.platform, false);
			// if still nothing found, use the first executable configuration
			if (!config.length) config = m_project.getDefaultConfiguration(settings.platform, true);
		}

		auto generator = createProjectGenerator("build", m_project);

		auto test_config = format("%s-test-%s", m_project.rootPackage.name.replace(".", "-").replace(":", "-"), config);

		BuildSettings lbuildsettings = settings.buildSettings;
		m_project.addBuildSettings(lbuildsettings, settings, config, null, true);
		if (lbuildsettings.targetType == TargetType.none) {
			logInfo(`Configuration '%s' has target type "none". Skipping test.`, config);
			return;
		}

		if (lbuildsettings.targetType == TargetType.executable && config == "unittest") {
			logInfo("Running custom 'unittest' configuration.", config);
			if (!custom_main_file.empty) logWarn("Ignoring custom main file.");
			settings.config = config;
		} else if (lbuildsettings.sourceFiles.empty) {
			logInfo(`No source files found in configuration '%s'. Falling back to "dub -b unittest".`, config);
			if (!custom_main_file.empty) logWarn("Ignoring custom main file.");
			settings.config = m_project.getDefaultConfiguration(settings.platform);
		} else {
			import std.algorithm : remove;

			logInfo(`Generating test runner configuration '%s' for '%s' (%s).`, test_config, config, lbuildsettings.targetType);

			BuildSettingsTemplate tcinfo = m_project.rootPackage.recipe.getConfiguration(config).buildSettings;
			tcinfo.targetType = TargetType.executable;
			tcinfo.targetName = test_config;
			// HACK for vibe.d's legacy main() behavior:
			tcinfo.versions[""] ~= "VibeCustomMain";
			m_project.rootPackage.recipe.buildSettings.versions[""] = m_project.rootPackage.recipe.buildSettings.versions.get("", null).remove!(v => v == "VibeDefaultMain");
			// TODO: remove this ^ once vibe.d has removed the default main implementation

			auto mainfil = tcinfo.mainSourceFile;
			if (!mainfil.length) mainfil = m_project.rootPackage.recipe.buildSettings.mainSourceFile;

			string custommodname;
			if (!custom_main_file.empty) {
				import std.path;
				tcinfo.sourceFiles[""] ~= custom_main_file.relativeTo(m_project.rootPackage.path).toNativeString();
				tcinfo.importPaths[""] ~= custom_main_file.parentPath.toNativeString();
				custommodname = custom_main_file.head.toString().baseName(".d");
			}

			// prepare the list of tested modules
			string[] import_modules;
			foreach (file; lbuildsettings.sourceFiles) {
				if (file.endsWith(".d")) {
					auto fname = NativePath(file).head.toString();
					if (NativePath(file).relativeTo(m_project.rootPackage.path) == NativePath(mainfil)) {
						logWarn("Excluding main source file %s from test.", mainfil);
						tcinfo.excludedSourceFiles[""] ~= mainfil;
						continue;
					}
					if (fname == "package.d") {
						logWarn("Excluding package.d file from test due to https://issues.dlang.org/show_bug.cgi?id=11847");
						continue;
					}
					import_modules ~= dub.internal.utils.determineModuleName(lbuildsettings, NativePath(file), m_project.rootPackage.path);
				}
			}

			// generate main file
			NativePath mainfile = getTempFile("dub_test_root", ".d");
			tcinfo.sourceFiles[""] ~= mainfile.toNativeString();
			tcinfo.mainSourceFile = mainfile.toNativeString();
			if (!m_dryRun) {
				auto fil = openFile(mainfile, FileMode.createTrunc);
				scope(exit) fil.close();
				fil.write("module dub_test_root;\n");
				fil.write("import std.typetuple;\n");
				foreach (mod; import_modules) fil.write(format("static import %s;\n", mod));
				fil.write("alias allModules = TypeTuple!(");
				foreach (i, mod; import_modules) {
					if (i > 0) fil.write(", ");
					fil.write(mod);
				}
				fil.write(");\n");
				if (custommodname.length) {
					fil.write(format("import %s;\n", custommodname));
				} else {
					fil.write(q{
						import std.stdio;
						import core.runtime;

						void main() { writeln("All unit tests have been run successfully."); }
						shared static this() {
							version (Have_tested) {
								import tested;
								import core.runtime;
								import std.exception;
								Runtime.moduleUnitTester = () => true;
								//runUnitTests!app(new JsonTestResultWriter("results.json"));
								enforce(runUnitTests!allModules(new ConsoleTestResultWriter), "Unit tests failed.");
							}
						}
					});
				}
			}
			m_project.rootPackage.recipe.configurations ~= ConfigurationInfo(test_config, tcinfo);
			m_project = new Project(m_packageManager, m_project.rootPackage);

			settings.config = test_config;
		}

		generator.generate(settings);
	}

	/** Prints the specified build settings necessary for building the root package.
	*/
	void listProjectData(GeneratorSettings settings, string[] requestedData, ListBuildSettingsFormat list_type)
	{
		import std.stdio;
		import std.ascii : newline;

		// Split comma-separated lists
		string[] requestedDataSplit =
			requestedData
			.map!(a => a.splitter(",").map!strip)
			.joiner()
			.array();

		auto data = m_project.listBuildSettings(settings, requestedDataSplit, list_type);

		string delimiter;
		final switch (list_type) with (ListBuildSettingsFormat) {
			case list: delimiter = newline ~ newline; break;
			case listNul: delimiter = "\0\0"; break;
			case commandLine: delimiter = " "; break;
			case commandLineNul: delimiter = "\0\0"; break;
		}

		write(data.joiner(delimiter));
		if (delimiter != "\0\0") writeln();
	}

	/// Cleans intermediate/cache files of the given package
	void cleanPackage(NativePath path)
	{
		logInfo("Cleaning package at %s...", path.toNativeString());
		enforce(!Package.findPackageFile(path).empty, "No package found.", path.toNativeString());

		// TODO: clear target files and copy files

		if (existsFile(path ~ ".dub/build")) rmdirRecurse((path ~ ".dub/build").toNativeString());
		if (existsFile(path ~ ".dub/obj")) rmdirRecurse((path ~ ".dub/obj").toNativeString());
	}

	/// Fetches the package matching the dependency and places it in the specified location.
	Package fetch(string packageId, const Dependency dep, PlacementLocation location, FetchOptions options, string reason = "")
	{
		Json pinfo;
		PackageSupplier supplier;
		foreach(ps; m_packageSuppliers){
			try {
				pinfo = ps.fetchPackageRecipe(packageId, dep, (options & FetchOptions.usePrerelease) != 0);
				if (pinfo.type == Json.Type.null_)
					continue;
				supplier = ps;
				break;
			} catch(Exception e) {
				logWarn("Package %s not found for %s: %s", packageId, ps.description, e.msg);
				logDebug("Full error: %s", e.toString().sanitize());
			}
		}
		enforce(pinfo.type != Json.Type.undefined, "No package "~packageId~" was found matching the dependency "~dep.toString());
		string ver = pinfo["version"].get!string;

		NativePath placement;
		final switch (location) {
			case PlacementLocation.local: placement = m_rootPath; break;
			case PlacementLocation.user: placement = m_dirs.localRepository ~ "packages/"; break;
			case PlacementLocation.system: placement = m_dirs.systemSettings ~ "packages/"; break;
		}

		// always upgrade branch based versions - TODO: actually check if there is a new commit available
		Package existing;
		try existing = m_packageManager.getPackage(packageId, ver, placement);
		catch (Exception e) {
			logWarn("Failed to load existing package %s: %s", ver, e.msg);
			logDiagnostic("Full error: %s", e.toString().sanitize);
		}

		if (options & FetchOptions.printOnly) {
			if (existing && existing.version_ != Version(ver))
				logInfo("A new version for %s is available (%s -> %s). Run \"dub upgrade %s\" to switch.",
					packageId, existing.version_, ver, packageId);
			return null;
		}

		if (existing) {
			if (!ver.startsWith("~") || !(options & FetchOptions.forceBranchUpgrade) || location == PlacementLocation.local) {
				// TODO: support git working trees by performing a "git pull" instead of this
				logDiagnostic("Package %s %s (%s) is already present with the latest version, skipping upgrade.",
					packageId, ver, placement);
				return existing;
			} else {
				logInfo("Removing %s %s to prepare replacement with a new version.", packageId, ver);
				if (!m_dryRun) m_packageManager.remove(existing);
			}
		}

		if (reason.length) logInfo("Fetching %s %s (%s)...", packageId, ver, reason);
		else logInfo("Fetching %s %s...", packageId, ver);
		if (m_dryRun) return null;

		logDebug("Acquiring package zip file");

		auto clean_package_version = ver[ver.startsWith("~") ? 1 : 0 .. $];
		clean_package_version = clean_package_version.replace("+", "_"); // + has special meaning for Optlink
		if (!placement.existsFile())
			mkdirRecurse(placement.toNativeString());
		NativePath dstpath = placement ~ (packageId ~ "-" ~ clean_package_version);
		if (!dstpath.existsFile())
			mkdirRecurse(dstpath.toNativeString());

		// Support libraries typically used with git submodules like ae.
		// Such libraries need to have ".." as import path but this can create
		// import path leakage.
		dstpath = dstpath ~ packageId;

		import std.datetime : seconds;
		auto lock = lockFile(dstpath.toNativeString() ~ ".lock", 30.seconds); // possibly wait for other dub instance
		if (dstpath.existsFile())
		{
			m_packageManager.refresh(false);
			return m_packageManager.getPackage(packageId, ver, dstpath);
		}

		if (!dep.url.empty) {
			auto tempDir = getTempFile(packageId);
			logInfo("tempDir: %s", tempDir);
			logInfo("Placing to %s... (dstpath: %s)", placement.toNativeString(), dstpath);
			import std.process;
			// TODO: do a proper git clone here
			// TODO: clone into temporary directory
			spawnProcess(["git", "clone", "--depth", "1", "https://github.com/wilzbach/d-bootstrap", tempDir.toNativeString]).wait;
			m_packageManager.storeLocalPackage(tempDir, "0.0.0", dstpath);
			//spawn(["rm", "-rf", defaultPlacementLocation ~ ".git");
		} else {

			// repeat download on corrupted zips, see #1336
			foreach_reverse (i; 0..3)
			{
				import std.zip : ZipException;

				auto path = getTempFile(packageId, ".zip");
				supplier.fetchPackage(path, packageId, dep, (options & FetchOptions.usePrerelease) != 0); // Q: continue on fail?
				scope(exit) std.file.remove(path.toNativeString());
				logDiagnostic("Placing to %s...", placement.toNativeString());

				try {
					return m_packageManager.storeFetchedPackage(path, pinfo, dstpath);
				} catch (ZipException e) {
					logInfo("Failed to extract zip archive for %s %s...", packageId, ver);
					// rethrow the exception at the end of the loop
					if (i == 0)
						throw e;
				}
			}
		}
		assert(0, "Should throw a ZipException instead.");
	}

	/** Removes a specific locally cached package.

		This will delete the package files from disk and removes the
		corresponding entry from the list of known packages.

		Params:
			pack = Package instance to remove
	*/
	void remove(in Package pack)
	{
		logInfo("Removing %s in %s", pack.name, pack.path.toNativeString());
		if (!m_dryRun) m_packageManager.remove(pack);
	}

	/// Compatibility overload. Use the version without a `force_remove` argument instead.
	void remove(in Package pack, bool force_remove)
	{
		remove(pack);
	}

	/// @see remove(string, string, RemoveLocation)
	enum RemoveVersionWildcard = "*";

	/** Removes one or more versions of a locally cached package.

		This will remove a given package with a specified version from the
		given location. It will remove at most one package, unless `version_`
		is set to `RemoveVersionWildcard`.

		Params:
			package_id = Name of the package to be removed
			location_ = Specifies the location to look for the given package
				name/version.
			resolve_version = Callback to select package version.
	*/
	void remove(string package_id, PlacementLocation location,
				scope size_t delegate(in Package[] packages) resolve_version)
	{
		enforce(!package_id.empty);
		if (location == PlacementLocation.local) {
			logInfo("To remove a locally placed package, make sure you don't have any data"
					~ "\nleft in it's directory and then simply remove the whole directory.");
			throw new Exception("dub cannot remove locally installed packages.");
		}

		Package[] packages;

		// Retrieve packages to be removed.
		foreach(pack; m_packageManager.getPackageIterator(package_id))
			if (m_packageManager.isManagedPackage(pack))
				packages ~= pack;

		// Check validity of packages to be removed.
		if(packages.empty) {
			throw new Exception("Cannot find package to remove. ("
				~ "id: '" ~ package_id ~ "', location: '" ~ to!string(location) ~ "'"
				~ ")");
		}

		// Sort package list in ascending version order
		packages.sort!((a, b) => a.version_ < b.version_);

		immutable idx = resolve_version(packages);
		if (idx == size_t.max)
			return;
		else if (idx != packages.length)
			packages = packages[idx .. idx + 1];

		logDebug("Removing %s packages.", packages.length);
		foreach(pack; packages) {
			try {
				remove(pack);
				logInfo("Removed %s, version %s.", package_id, pack.version_);
			} catch (Exception e) {
				logError("Failed to remove %s %s: %s", package_id, pack.version_, e.msg);
				logInfo("Continuing with other packages (if any).");
			}
		}
	}

	/// Compatibility overload. Use the version without a `force_remove` argument instead.
	void remove(string package_id, PlacementLocation location, bool force_remove,
				scope size_t delegate(in Package[] packages) resolve_version)
	{
		remove(package_id, location, resolve_version);
	}

	/** Removes a specific version of a package.

		Params:
			package_id = Name of the package to be removed
			version_ = Identifying a version or a wild card. If an empty string
				is passed, the package will be removed from the location, if
				there is only one version retrieved. This will throw an
				exception, if there are multiple versions retrieved.
			location_ = Specifies the location to look for the given package
				name/version.
	 */
	void remove(string package_id, string version_, PlacementLocation location)
	{
		remove(package_id, location, (in packages) {
			if (version_ == RemoveVersionWildcard)
				return packages.length;
			if (version_.empty && packages.length > 1) {
				logError("Cannot remove package '" ~ package_id ~ "', there are multiple possibilities at location\n"
						 ~ "'" ~ to!string(location) ~ "'.");
				logError("Available versions:");
				foreach(pack; packages)
					logError("  %s", pack.version_);
				throw new Exception("Please specify a individual version using --version=... or use the"
									~ " wildcard --version=" ~ RemoveVersionWildcard ~ " to remove all versions.");
			}
			foreach (i, p; packages) {
				if (p.version_ == Version(version_))
					return i;
			}
			throw new Exception("Cannot find package to remove. ("
				~ "id: '" ~ package_id ~ "', version: '" ~ version_ ~ "', location: '" ~ to!string(location) ~ "'"
				~ ")");
		});
	}

	/// Compatibility overload. Use the version without a `force_remove` argument instead.
	void remove(string package_id, string version_, PlacementLocation location, bool force_remove)
	{
		remove(package_id, version_, location);
	}

	/** Adds a directory to the list of locally known packages.

		Forwards to `PackageManager.addLocalPackage`.

		Params:
			path = Path to the package
			ver = Optional version to associate with the package (can be left
				empty)
			system = Make the package known system wide instead of user wide
				(requires administrator privileges).

		See_Also: `removeLocalPackage`
	*/
	void addLocalPackage(string path, string ver, bool system)
	{
		if (m_dryRun) return;
		m_packageManager.addLocalPackage(makeAbsolute(path), ver, system ? LocalPackageType.system : LocalPackageType.user);
	}

	/** Removes a directory from the list of locally known packages.

		Forwards to `PackageManager.removeLocalPackage`.

		Params:
			path = Path to the package
			system = Make the package known system wide instead of user wide
				(requires administrator privileges).

		See_Also: `addLocalPackage`
	*/
	void removeLocalPackage(string path, bool system)
	{
		if (m_dryRun) return;
		m_packageManager.removeLocalPackage(makeAbsolute(path), system ? LocalPackageType.system : LocalPackageType.user);
	}

	/** Registers a local directory to search for packages to use for satisfying
		dependencies.

		Params:
			path = Path to a directory containing package directories
			system = Make the package known system wide instead of user wide
				(requires administrator privileges).

		See_Also: `removeSearchPath`
	*/
	void addSearchPath(string path, bool system)
	{
		if (m_dryRun) return;
		m_packageManager.addSearchPath(makeAbsolute(path), system ? LocalPackageType.system : LocalPackageType.user);
	}

	/** Unregisters a local directory search path.

		Params:
			path = Path to a directory containing package directories
			system = Make the package known system wide instead of user wide
				(requires administrator privileges).

		See_Also: `addSearchPath`
	*/
	void removeSearchPath(string path, bool system)
	{
		if (m_dryRun) return;
		m_packageManager.removeSearchPath(makeAbsolute(path), system ? LocalPackageType.system : LocalPackageType.user);
	}

	/** Queries all package suppliers with the given query string.

		Returns a list of tuples, where the first entry is the human readable
		name of the package supplier and the second entry is the list of
		matched packages.

		See_Also: `PackageSupplier.searchPackages`
	*/
	auto searchPackages(string query)
	{
		import std.typecons : Tuple, tuple;
		Tuple!(string, PackageSupplier.SearchResult[])[] results;
		foreach (ps; this.m_packageSuppliers) {
			try
				results ~= tuple(ps.description, ps.searchPackages(query));
			catch (Exception e) {
				logWarn("Searching %s for '%s' failed: %s", ps.description, query, e.msg);
			}
		}
		return results.filter!(tup => tup[1].length);
	}

	/** Returns a list of all available versions (including branches) for a
		particular package.

		The list returned is based on the registered package suppliers. Local
		packages are not queried in the search for versions.

		See_also: `getLatestVersion`
	*/
	Version[] listPackageVersions(string name)
	{
		Version[] versions;
		foreach (ps; this.m_packageSuppliers) {
			try versions ~= ps.getVersions(name);
			catch (Exception e) {
				logWarn("Failed to get versions for package %s on provider %s: %s", name, ps.description, e.msg);
			}
		}
		return versions.sort().uniq.array;
	}

	/** Returns the latest available version for a particular package.

		This function returns the latest numbered version of a package. If no
		numbered versions are available, it will return an available branch,
		preferring "~master".

		Params:
			package_name: The name of the package in question.
			prefer_stable: If set to `true` (the default), returns the latest
				stable version, even if there are newer pre-release versions.

		See_also: `listPackageVersions`
	*/
	Version getLatestVersion(string package_name, bool prefer_stable = true)
	{
		auto vers = listPackageVersions(package_name);
		enforce(!vers.empty, "Failed to find any valid versions for a package name of '"~package_name~"'.");
		auto final_versions = vers.filter!(v => !v.isBranch && !v.isPreRelease).array;
		if (prefer_stable && final_versions.length) return final_versions[$-1];
		else if (vers[$-1].isBranch) return vers[$-1];
		else return vers[$-1];
	}

	/** Initializes a directory with a package skeleton.

		Params:
			path = Path of the directory to create the new package in. The
				directory will be created if it doesn't exist.
			deps = List of dependencies to add to the package recipe.
			type = Specifies the type of the application skeleton to use.
			format = Determines the package recipe format to use.
			recipe_callback = Optional callback that can be used to
				customize the recipe before it gets written.
	*/
	void createEmptyPackage(NativePath path, string[] deps, string type,
		PackageFormat format = PackageFormat.sdl,
		scope void delegate(ref PackageRecipe, ref PackageFormat) recipe_callback = null)
	{
		if (!path.absolute) path = m_rootPath ~ path;
		path.normalize();

		string[string] depVers;
		string[] notFound; // keep track of any failed packages in here
		foreach (dep; deps) {
			Version ver;
			try {
				ver = getLatestVersion(dep);
				depVers[dep] = ver.isBranch ? ver.toString() : "~>" ~ ver.toString();
			} catch (Exception e) {
				notFound ~= dep;
			}
		}

		if(notFound.length > 1){
			throw new Exception(.format("Couldn't find packages: %-(%s, %).", notFound));
		}
		else if(notFound.length == 1){
			throw new Exception(.format("Couldn't find package: %-(%s, %).", notFound));
		}

		if (m_dryRun) return;

		initPackage(path, depVers, type, format, recipe_callback);

		//Act smug to the user.
		logInfo("Successfully created an empty project in '%s'.", path.toNativeString());
	}

	/** Converts the package recipe of the loaded root package to the given format.

		Params:
			destination_file_ext = The file extension matching the desired
				format. Possible values are "json" or "sdl".
			print_only = Print the converted recipe instead of writing to disk
	*/
	void convertRecipe(string destination_file_ext, bool print_only = false)
	{
		import std.path : extension;
		import std.stdio : stdout;
		import dub.recipe.io : serializePackageRecipe, writePackageRecipe;

		if (print_only) {
			auto dst = stdout.lockingTextWriter;
			serializePackageRecipe(dst, m_project.rootPackage.rawRecipe, "dub."~destination_file_ext);
			return;
		}

		auto srcfile = m_project.rootPackage.recipePath;
		auto srcext = srcfile.head.toString().extension;
		if (srcext == "."~destination_file_ext) {
			logInfo("Package format is already %s.", destination_file_ext);
			return;
		}

		writePackageRecipe(srcfile.parentPath ~ ("dub."~destination_file_ext), m_project.rootPackage.rawRecipe);
		removeFile(srcfile);
	}

	/** Runs DDOX to generate or serve documentation.

		Params:
			run = If set to true, serves documentation on a local web server.
				Otherwise generates actual HTML files.
			generate_args = Additional command line arguments to pass to
				"ddox generate-html" or "ddox serve-html".
	*/
	void runDdox(bool run, string[] generate_args = null)
	{
		import std.process : browse;

		if (m_dryRun) return;

		// allow to choose a custom ddox tool
		auto tool = m_project.rootPackage.recipe.ddoxTool;
		if (tool.empty) tool = "ddox";

		auto tool_pack = m_packageManager.getBestPackage(tool, ">=0.0.0");
		if (!tool_pack) tool_pack = m_packageManager.getBestPackage(tool, "~master");
		if (!tool_pack) {
			logInfo("%s is not present, getting and storing it user wide", tool);
			tool_pack = fetch(tool, Dependency(">=0.0.0"), defaultPlacementLocation, FetchOptions.none);
		}

		auto ddox_dub = new Dub(null, m_packageSuppliers);
		ddox_dub.loadPackage(tool_pack.path);
		ddox_dub.upgrade(UpgradeOptions.select);

		auto compiler_binary = this.defaultCompiler;

		GeneratorSettings settings;
		settings.config = "application";
		settings.compiler = getCompiler(compiler_binary); // TODO: not using --compiler ???
		settings.platform = settings.compiler.determinePlatform(settings.buildSettings, compiler_binary);
		settings.buildType = "debug";
		settings.run = true;

		auto filterargs = m_project.rootPackage.recipe.ddoxFilterArgs.dup;
		if (filterargs.empty) filterargs = ["--min-protection=Protected", "--only-documented"];

		settings.runArgs = "filter" ~ filterargs ~ "docs.json";
		ddox_dub.generateProject("build", settings);

		auto p = tool_pack.path;
		p.endsWithSlash = true;
		auto tool_path = p.toNativeString();

		if (run) {
			settings.runArgs = ["serve-html", "--navigation-type=ModuleTree", "docs.json", "--web-file-dir="~tool_path~"public"] ~ generate_args;
			browse("http://127.0.0.1:8080/");
		} else {
			settings.runArgs = ["generate-html", "--navigation-type=ModuleTree", "docs.json", "docs"] ~ generate_args;
		}
		ddox_dub.generateProject("build", settings);

		if (!run) {
			// TODO: ddox should copy those files itself
			version(Windows) runCommand("xcopy /S /D "~tool_path~"public\\* docs\\");
			else runCommand("rsync -ru '"~tool_path~"public/' docs/");
		}
	}

	private void updatePackageSearchPath()
	{
		if (!m_overrideSearchPath.empty) {
			m_packageManager.disableDefaultSearchPaths = true;
			m_packageManager.searchPath = [m_overrideSearchPath];
		} else {
			auto p = environment.get("DUBPATH");
			NativePath[] paths;

			version(Windows) enum pathsep = ";";
			else enum pathsep = ":";
			if (p.length) paths ~= p.split(pathsep).map!(p => NativePath(p))().array();
			m_packageManager.disableDefaultSearchPaths = false;
			m_packageManager.searchPath = paths;
		}
	}

	private void determineDefaultCompiler()
	{
		import std.file : thisExePath;
		import std.path : buildPath, dirName, expandTilde, isAbsolute, isDirSeparator;
		import std.process : environment;
		import std.range : front;

		m_defaultCompiler = m_config.defaultCompiler.expandTilde;
		if (m_defaultCompiler.length && m_defaultCompiler.isAbsolute)
			return;

		static immutable BinaryPrefix = `$DUB_BINARY_PATH`;
		if(m_defaultCompiler.startsWith(BinaryPrefix))
		{
			m_defaultCompiler = thisExePath().dirName() ~ m_defaultCompiler[BinaryPrefix.length .. $];
			return;
		}

		if (!find!isDirSeparator(m_defaultCompiler).empty)
			throw new Exception("defaultCompiler specified in a DUB config file cannot use an unqualified relative path:\n\n" ~ m_defaultCompiler ~
			"\n\nUse \"$DUB_BINARY_PATH/../path/you/want\" instead.");

		version (Windows) enum sep = ";", exe = ".exe";
		version (Posix) enum sep = ":", exe = "";

		auto compilers = ["dmd", "gdc", "gdmd", "ldc2", "ldmd2"];
		// If a compiler name is specified, look for it next to dub.
		// Otherwise, look for any of the common compilers adjacent to dub.
		if (m_defaultCompiler.length)
		{
			string compilerPath = buildPath(thisExePath().dirName(), m_defaultCompiler ~ exe);
			if (existsFile(compilerPath))
			{
				m_defaultCompiler = compilerPath;
				return;
			}
		}
		else
		{
			auto nextFound = compilers.find!(bin => existsFile(buildPath(thisExePath().dirName(), bin ~ exe)));
			if (!nextFound.empty)
			{
				m_defaultCompiler = buildPath(thisExePath().dirName(),  nextFound.front ~ exe);
				return;
			}
		}

		// If nothing found next to dub, search the user's PATH, starting
		// with the compiler name from their DUB config file, if specified.
		if (m_defaultCompiler.length)
			compilers = m_defaultCompiler ~ compilers;
		auto paths = environment.get("PATH", "").splitter(sep).map!NativePath;
		auto res = compilers.find!(bin => paths.canFind!(p => existsFile(p ~ (bin~exe))));
		m_defaultCompiler = res.empty ? compilers[0] : res.front;
	}

	private NativePath makeAbsolute(NativePath p) const { return p.absolute ? p : m_rootPath ~ p; }
	private NativePath makeAbsolute(string p) const { return makeAbsolute(NativePath(p)); }
}


/// Option flags for `Dub.fetch`
enum FetchOptions
{
	none = 0,
	forceBranchUpgrade = 1<<0,
	usePrerelease = 1<<1,
	forceRemove = 1<<2, /// Deprecated, does nothing.
	printOnly = 1<<3,
}

/// Option flags for `Dub.upgrade`
enum UpgradeOptions
{
	none = 0,
	upgrade = 1<<1, /// Upgrade existing packages
	preRelease = 1<<2, /// inclde pre-release versions in upgrade
	forceRemove = 1<<3, /// Deprecated, does nothing.
	select = 1<<4, /// Update the dub.selections.json file with the upgraded versions
	dryRun = 1<<5, /// Instead of downloading new packages, just print a message to notify the user of their existence
	/*deprecated*/ printUpgradesOnly = dryRun, /// deprecated, use dryRun instead
	/*deprecated*/ useCachedResult = 1<<6, /// deprecated, has no effect
	noSaveSelections = 1<<7, /// Don't store updated selections on disk
}

/// Determines which of the default package suppliers are queried for packages.
enum SkipPackageSuppliers {
	none,       /// Uses all configured package suppliers.
	standard,   /// Does not use the default package suppliers (`defaultPackageSuppliers`).
	configured, /// Does not use default suppliers or suppliers configured in DUB's configuration file
	all         /// Uses only manually specified package suppliers.
}

private class DependencyVersionResolver : DependencyResolver!(Dependency, Dependency) {
	protected {
		Dub m_dub;
		UpgradeOptions m_options;
		Dependency[][string] m_packageVersions;
		Package[string] m_remotePackages;
		SelectedVersions m_selectedVersions;
		Package m_rootPackage;
		bool[string] m_packagesToUpgrade;
		Package[PackageDependency] m_packages;
		TreeNodes[][TreeNode] m_children;
	}


	this(Dub dub, UpgradeOptions options)
	{
		m_dub = dub;
		m_options = options;
	}

	void addPackageToUpgrade(string name)
	{
		m_packagesToUpgrade[name] = true;
	}

	Dependency[string] resolve(Package root, SelectedVersions selected_versions)
	{
		m_rootPackage = root;
		m_selectedVersions = selected_versions;
		logInfo("dub.resolve: %s", root.name);
		auto dep = Dependency(root.version_);
		return super.resolve(TreeNode(root.name, dep), (m_options & UpgradeOptions.printUpgradesOnly) == 0);
	}

	protected bool isFixedPackage(string pack)
	{
		return m_packagesToUpgrade !is null && pack !in m_packagesToUpgrade;
	}

	protected override Dependency[] getAllConfigs(string pack)
	{
		if (auto pvers = pack in m_packageVersions)
			return *pvers;

		if ((!(m_options & UpgradeOptions.upgrade) || isFixedPackage(pack)) && m_selectedVersions.hasSelectedVersion(pack)) {
			auto ret = [m_selectedVersions.getSelectedVersion(pack)];
			logDiagnostic("Using fixed selection %s %s", pack, ret[0]);
			m_packageVersions[pack] = ret;
			return ret;
		}

		logDiagnostic("Search for versions of %s (%s package suppliers)", pack, m_dub.m_packageSuppliers.length);
		Version[] versions;
		foreach (p; m_dub.packageManager.getPackageIterator(pack))
			versions ~= p.version_;

		foreach (ps; m_dub.m_packageSuppliers) {
			try {
				auto vers = ps.getVersions(pack);
				vers.reverse();
				if (!vers.length) {
					logDiagnostic("No versions for %s for %s", pack, ps.description);
					continue;
				}

				versions ~= vers;
				break;
			} catch (Exception e) {
				logWarn("Package %s not found in %s: %s", pack, ps.description, e.msg);
				logDebug("Full error: %s", e.toString().sanitize);
			}
		}

		// sort by version, descending, and remove duplicates
		versions = versions.sort!"a>b".uniq.array;

		// move pre-release versions to the back of the list if no preRelease flag is given
		if (!(m_options & UpgradeOptions.preRelease))
			versions = versions.filter!(v => !v.isPreRelease).array ~ versions.filter!(v => v.isPreRelease).array;

		// filter out invalid/unreachable dependency specs
		versions = versions.filter!((v) {
				bool valid = getPackage(pack, Dependency(v)) !is null;
				if (!valid) logDiagnostic("Excluding invalid dependency specification %s %s from dependency resolution process.", pack, v);
				return valid;
			}).array;

		if (!versions.length) logDiagnostic("Nothing found for %s", pack);
		else logDiagnostic("Return for %s: %s", pack, versions);

		auto ret = versions.map!(v => Dependency(v)).array;
		m_packageVersions[pack] = ret;
		return ret;
	}

	protected override Dependency[] getSpecificConfigs(string pack, TreeNodes nodes)
	{
		if (!nodes.configs.path.empty && getPackage(pack, nodes.configs)) return [nodes.configs];
		else return null;
	}


	protected override TreeNodes[] getChildren(TreeNode node)
	{
		if (auto pc = node in m_children)
			return *pc;
		auto ret = getChildrenRaw(node);
		m_children[node] = ret;
		return ret;
	}

	private final TreeNodes[] getChildrenRaw(TreeNode node)
	{
		import std.array : appender;
		auto ret = appender!(TreeNodes[]);
		auto pack = getPackage(node.pack, node.config);
		if (!pack) {
			// this can hapen when the package description contains syntax errors
			logDebug("Invalid package in dependency tree: %s %s", node.pack, node.config);
			return null;
		}
		auto basepack = pack.basePackage;

		foreach (d; pack.getAllDependenciesRange()) {
			auto dbasename = getBasePackageName(d.name);

			// detect dependencies to the root package (or sub packages thereof)
			if (dbasename == basepack.name) {
				auto absdeppath = d.spec.mapToPath(pack.path).path;
				absdeppath.endsWithSlash = true;
				auto subpack = m_dub.m_packageManager.getSubPackage(basepack, getSubPackageName(d.name), true);
				if (subpack) {
					auto desireddeppath = d.name == dbasename ? basepack.path : subpack.path;
					desireddeppath.endsWithSlash = true;
					enforce(d.spec.path.empty || absdeppath == desireddeppath,
						format("Dependency from %s to root package references wrong path: %s vs. %s",
							node.pack, absdeppath.toNativeString(), desireddeppath.toNativeString()));
				}
				ret ~= TreeNodes(d.name, node.config);
				continue;
			}

			DependencyType dt;
			if (d.spec.optional) {
				if (d.spec.default_) dt = DependencyType.optionalDefault;
				else dt = DependencyType.optional;
			} else dt = DependencyType.required;

			Dependency dspec = d.spec.mapToPath(pack.path);

			// if not upgrading, use the selected version
			if (!(m_options & UpgradeOptions.upgrade) && m_selectedVersions && m_selectedVersions.hasSelectedVersion(dbasename))
				dspec = m_selectedVersions.getSelectedVersion(dbasename);

			// keep selected optional dependencies and avoid non-selected optional-default dependencies by default
			if (m_selectedVersions && !m_selectedVersions.bare) {
				if (dt == DependencyType.optionalDefault && !m_selectedVersions.hasSelectedVersion(dbasename))
					dt = DependencyType.optional;
				else if (dt == DependencyType.optional && m_selectedVersions.hasSelectedVersion(dbasename))
					dt = DependencyType.optionalDefault;
			}

			ret ~= TreeNodes(d.name, dspec, dt);
		}
		return ret.data;
	}

	protected override bool matches(Dependency configs, Dependency config)
	{
		if (!configs.path.empty) return configs.path == config.path;
		return configs.merge(config).valid;
	}

	private Package getPackage(string name, Dependency dep)
	{
		auto key = PackageDependency(name, dep);
		if (auto pp = key in m_packages)
			return *pp;
		auto p = getPackageRaw(name, dep);
		m_packages[key] = p;
		return p;
	}

	private Package getPackageRaw(string name, Dependency dep)
	{
		auto basename = getBasePackageName(name);

		// for sub packages, first try to get them from the base package
		if (basename != name) {
			auto subname = getSubPackageName(name);
			auto basepack = getPackage(basename, dep);
			if (!basepack) return null;
			if (auto sp = m_dub.m_packageManager.getSubPackage(basepack, subname, true)) {
				return sp;
			} else if (!basepack.subPackages.canFind!(p => p.path.length)) {
				// note: external sub packages are handled further below
				auto spr = basepack.getInternalSubPackage(subname);
				if (!spr.isNull) {
					auto sp = new Package(spr, basepack.path, basepack);
					m_remotePackages[sp.name] = sp;
					return sp;
				} else {
					logDiagnostic("Sub package %s doesn't exist in %s %s.", name, basename, dep.version_);
					return null;
				}
			} else if (auto ret = m_dub.m_packageManager.getBestPackage(name, dep)) {
				return ret;
			} else {
				logDiagnostic("External sub package %s %s not found.", name, dep.version_);
				return null;
			}
		}

		// shortcut if the referenced package is the root package
		if (basename == m_rootPackage.basePackage.name)
			return m_rootPackage.basePackage;

		if (!dep.path.empty) {
			try {
				auto ret = m_dub.packageManager.getOrLoadPackage(dep.path);
				if (dep.matches(ret.version_)) return ret;
			} catch (Exception e) {
				logDiagnostic("Failed to load path based dependency %s: %s", name, e.msg);
				logDebug("Full error: %s", e.toString().sanitize);
				return null;
			}
		}

		if (auto ret = m_dub.m_packageManager.getBestPackage(name, dep))
			return ret;

		if (!dep.url.empty)
		{
			logInfo("Returning fake URL package");
			Json json = Json.emptyObject;
			json["name"] = name;
			json["version"] = "1.2.3";
			return new Package(json);
		}

		auto key = name ~ ":" ~ dep.version_.toString();
		if (auto ret = key in m_remotePackages)
			return *ret;

		auto prerelease = (m_options & UpgradeOptions.preRelease) != 0;

		auto rootpack = name.split(":")[0];

		foreach (ps; m_dub.m_packageSuppliers) {
			if (rootpack == name) {
				try {
					auto desc = ps.fetchPackageRecipe(name, dep, prerelease);
					if (desc.type == Json.Type.null_)
						continue;
					auto ret = new Package(desc);
					m_remotePackages[key] = ret;
					return ret;
				} catch (Exception e) {
					logDiagnostic("Metadata for %s %s could not be downloaded from %s: %s", name, dep, ps.description, e.msg);
					logDebug("Full error: %s", e.toString().sanitize);
				}
			} else {
				logDiagnostic("Package %s not found in base package description (%s). Downloading whole package.", name, dep.version_.toString());
				try {
					FetchOptions fetchOpts;
					fetchOpts |= prerelease ? FetchOptions.usePrerelease : FetchOptions.none;
					m_dub.fetch(rootpack, dep, m_dub.defaultPlacementLocation, fetchOpts, "need sub package description");
					auto ret = m_dub.m_packageManager.getBestPackage(name, dep);
					if (!ret) {
						logWarn("Package %s %s doesn't have a sub package %s", rootpack, dep.version_, name);
						return null;
					}
					m_remotePackages[key] = ret;
					return ret;
				} catch (Exception e) {
					logDiagnostic("Package %s could not be downloaded from %s: %s", rootpack, ps.description, e.msg);
					logDebug("Full error: %s", e.toString().sanitize);
				}
			}
		}

		m_remotePackages[key] = null;

		logWarn("Package %s %s could not be loaded either locally, or from the configured package registries.", name, dep);
		return null;
	}
}

private struct SpecialDirs {
	NativePath temp;
	NativePath userSettings;
	NativePath systemSettings;
	NativePath localRepository;
}

private class DubConfig {
	private {
		DubConfig m_parentConfig;
		Json m_data;
	}

	this(Json data, DubConfig parent_config)
	{
		m_data = data;
		m_parentConfig = parent_config;
	}

	@property string[] registryURLs()
	{
		string[] ret;
		if (auto pv = "registryUrls" in m_data)
			ret = (*pv).deserializeJson!(string[]);
		if (m_parentConfig) ret ~= m_parentConfig.registryURLs;
		return ret;
	}

	@property SkipPackageSuppliers skipRegistry()
	{
		if(auto pv = "skipRegistry" in m_data)
			return to!SkipPackageSuppliers((*pv).get!string);

		if (m_parentConfig)
			return m_parentConfig.skipRegistry;

		return SkipPackageSuppliers.none;
	}

	@property NativePath[] customCachePaths()
	{
		import std.algorithm.iteration : map;
		import std.array : array;

		NativePath[] ret;
		if (auto pv = "customCachePaths" in m_data)
			ret = (*pv).deserializeJson!(string[])
				.map!(s => NativePath(s))
				.array;
		if (m_parentConfig)
			ret ~= m_parentConfig.customCachePaths;
		return ret;
	}

	@property string defaultCompiler()
	const {
		if (auto pv = "defaultCompiler" in m_data)
			return pv.get!string;
		if (m_parentConfig) return m_parentConfig.defaultCompiler;
		return null;
	}

	@property string defaultArchitecture()
	const {
		if(auto pv = "defaultArchitecture" in m_data)
			return (*pv).get!string;
		if (m_parentConfig) return m_parentConfig.defaultArchitecture;
		return null;
	}
}
