/**
	Stuff with dependencies.

	Copyright: © 2012-2013 Matthias Dondorff
	License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
	Authors: Matthias Dondorff, Sönke Ludwig
*/
module dub.dependency;

import dub.internal.utils;
import dub.internal.vibecompat.core.log;
import dub.internal.vibecompat.core.file;
import dub.internal.vibecompat.data.json;
import dub.internal.vibecompat.inet.url;
import dub.package_;
import dub.semver;

import std.algorithm;
import std.array;
import std.exception;
import std.regex;
import std.string;
import std.typecons;
static import std.compiler;


/**
	Representing a dependency, which is basically a version string and a
	compare methode, e.g. '>=1.0.0 <2.0.0' (i.e. a space separates the two
	version numbers)
*/
struct Dependency {
	private {
		// Shortcut to create >=0.0.0
		enum ANY_IDENT = "*";
		Interval!Version m_versionRange;
		Path m_path;
		bool m_optional = false;
	}

	// A Dependency, which matches every valid version.
	static @property any() { return Dependency(ANY_IDENT); }
	static @property invalid() { return Dependency.init; }
	static assert(!invalid.valid);

	alias ANY = any;
	alias INVALID = invalid;

	this(string ves)
	{
		this.versionSpec = ves;
	}

	this(in Version ver)
	{
		m_versionRange = Interval!Version(ver, ver, "[]");
	}

	this(Path path)
	{
		this(ANY_IDENT);
		m_path = path;
	}

	@property void path(Path value) { m_path = value; }
	@property Path path() const { return m_path; }
	@property bool optional() const { return m_optional; }
	@property void optional(bool optional) { m_optional = optional; }
	@property bool isExactVersion() const { return m_versionRange.singular; }

	@property Version version_()
	const {
		enforce(m_versionRange.singular, "Dependency "~versionString~" is no exact version.");
		return m_versionRange.min;
	}

	@property string versionString()
	const {
		if (m_versionRange.empty) return "invalid";
		if (m_versionRange.singular) return m_versionRange.min.toString();
		if (m_versionRange == any.m_versionRange) return "*";

		string r;
		if (m_versionRange.min != Version.RELEASE || !m_versionRange.minInclusive)
			r = (m_versionRange.minInclusive ? ">=" : ">") ~ m_versionRange.min.toString();
		if (m_versionRange.max != Version.HEAD || !m_versionRange.maxInclusive)
			r ~= (r.length==0 ? "" : " ") ~ (m_versionRange.maxInclusive ? "<=" : "<") ~ m_versionRange.max.toString();
		return r;
	}

	@property void versionSpec(string ves)
	{
		enforce(ves.length > 0);
		string orig = ves;

		if (ves == ANY_IDENT) {
			// Any version is good.
			ves = ">=0.0.0";
		}

		if (ves.startsWith("~>")) {
			// Shortcut: "~>x.y.z" variant. Last non-zero number will indicate
			// the base for this so something like this: ">=x.y.z <x.(y+1).z"
			m_versionRange = Interval!Version(Version(expandVersion(ves[2 .. $])), Version(bumpVersion(ves[2 .. $])), "[)");
		} else if (ves[0] == Version.BRANCH_IDENT) {
			m_versionRange = Interval!Version(Version(ves), Version(ves), "[]");
		} else if (std.string.indexOf("><=", ves[0]) == -1) {
			m_versionRange = Interval!Version(Version(ves), Version(ves), "[]");
		} else {
			auto cmpa = skipComp(ves);
			size_t idx2 = std.string.indexOf(ves, " ");
			if (idx2 == -1) {
				if (cmpa == "<=" || cmpa == "<") {
					m_versionRange = Interval!Version(Version.RELEASE, Version(ves), cmpa == "<=" ? "[]" : "[)");
				} else if (cmpa == ">=" || cmpa == ">") {
					m_versionRange = Interval!Version(Version(ves), Version.HEAD, cmpa == ">=" ? "[]" : "(]");
				} else {
					m_versionRange = Interval!Version(Version(ves), Version(ves), "[]");
				}
			} else {
				enforce(cmpa == ">" || cmpa == ">=", "First comparison operator expected to be either > or >=, not "~cmpa);
				assert(ves[idx2] == ' ');
				auto vmin = Version(ves[0..idx2]);
				bool vmininc = cmpa == ">=";
				string v2 = ves[idx2+1..$];
				auto cmpb = skipComp(v2);
				enforce(cmpb == "<" || cmpb == "<=", "Second comparison operator expected to be either < or <=, not "~cmpb);
				auto vmax = Version(v2);
				bool vmaxinc = cmpb == "<=";

				enforce(!vmin.isBranch && !vmax.isBranch, format("Cannot compare branches: %s", ves));
				enforce(vmin <= vmax, "First version must not be greater than the second one.");

				m_versionRange = Interval!Version(vmin, vmax, vmininc ? vmaxinc ? "[]" : "[)" : vmaxinc ? "(]" : "()");
			}
		}
	}

	Dependency mapToPath(Path path)
	const {
		if (m_path.empty || m_path.absolute) return this;
		else {
			Dependency ret = this;
			ret.path = path ~ ret.path;
			return ret;
		}
	}

	string toString()()
	const {
		auto ret = versionString;
		if (optional) ret ~= " (optional)";
		if (!path.empty) ret ~= " @"~path.toNativeString();
		return ret;
	}

	Json toJson() const {
		Json json;
		if( path.empty && !optional ){
			json = Json(this.versionString);
		} else {
			json = Json.emptyObject;
			json["version"] = this.versionString;
			if (!path.empty) json["path"] = path.toString();
			if (optional) json["optional"] = true;
		}
		return json;
	}

	unittest {
		Dependency d = Dependency("==1.0.0");
		assert(d.toJson() == Json("1.0.0"), "Failed: " ~ d.toJson().toPrettyString());
		d = fromJson((fromJson(d.toJson())).toJson());
		assert(d == Dependency("1.0.0"));
		assert(d.toJson() == Json("1.0.0"), "Failed: " ~ d.toJson().toPrettyString());
	}

	static Dependency fromJson(Json verspec) {
		Dependency dep;
		if( verspec.type == Json.Type.object ){
			if( auto pp = "path" in verspec ) {
				if (auto pv = "version" in verspec)
					logDiagnostic("Ignoring version specification (%s) for path based dependency %s", pv.get!string, pp.get!string);

				dep = Dependency.ANY;
				dep.path = Path(verspec.path.get!string);
			} else {
				enforce("version" in verspec, "No version field specified!");
				auto ver = verspec["version"].get!string;
				// Using the string to be able to specifiy a range of versions.
				dep = Dependency(ver);
			}
			if( auto po = "optional" in verspec ) {
				dep.optional = verspec.optional.get!bool;
			}
		} else {
			// canonical "package-id": "version"
			dep = Dependency(verspec.get!string);
		}
		return dep;
	}

	unittest {
		assert(fromJson(parseJsonString("\">=1.0.0 <2.0.0\"")) == Dependency(">=1.0.0 <2.0.0"));
		Dependency parsed = fromJson(parseJsonString(`
		{
			"version": "2.0.0",
			"optional": true,
			"path": "path/to/package"
		}
			`));
		Dependency d = Dependency.ANY; // supposed to ignore the version spec
		d.optional = true;
		d.path = Path("path/to/package");
		assert(d == parsed);
		// optional and path not checked by opEquals.
		assert(d.optional == parsed.optional);
		assert(d.path == parsed.path);
	}

	bool opEquals(in Dependency o)
	const {
		// TODO(mdondorff): Check if not comparing the path is correct for all clients.
		if (m_optional != o.m_optional) return false;
		return m_versionRange == o.m_versionRange;
	}

	int opCmp(in Dependency o)
	const {
		if (m_versionRange != o.m_versionRange)
			return m_versionRange.opCmp(o.m_versionRange);
		if (m_optional != o.m_optional) return m_optional ? -1 : 1;
		return 0;
	}

	hash_t toHash() const nothrow @trusted  {
		try {
			auto strhash = &typeid(string).getHash;
			auto str = this.toString();
			return strhash(&str);
		} catch (Exception) assert(false);
	}

	bool valid() const { return !m_versionRange.empty; }

	bool matches(string vers) const { return matches(Version(vers)); }
	bool matches(const(Version) v) const { return matches(v); }
	bool matches(ref const(Version) v) const {
		if (m_versionRange == any.m_versionRange)
			return true;
		//logDebug(" try match: %s with: %s", v, this);

		return m_versionRange.contains(v);
	}

	/// Merges to versions
	Dependency merge(ref const(Dependency) o)
	const {
		if (this == ANY) return o;
		if (o == ANY) return this;

		if (!this.valid || !o.valid) return INVALID;
		if (this.path != o.path) return INVALID;

		Dependency ret;
		ret.m_path = m_path;
		ret.m_optional = m_optional && o.m_optional;
		ret.m_versionRange = m_versionRange & o.m_versionRange;
		return ret;
	}

	private static bool isDigit(char ch) { return ch >= '0' && ch <= '9'; }
	private static string skipComp(ref string c) {
		size_t idx = 0;
		while (idx < c.length && !isDigit(c[idx]) && c[idx] != Version.BRANCH_IDENT) idx++;
		enforce(idx < c.length, "Expected version number in version spec: "~c);
		string cmp = idx==c.length-1||idx==0? ">=" : c[0..idx];
		c = c[idx..$];
		switch(cmp) {
			default: enforce(false, "No/Unknown comparision specified: '"~cmp~"'"); return ">=";
			case ">=": goto case; case ">": goto case;
			case "<=": goto case; case "<": goto case;
			case "==": return cmp;
		}
	}
}

unittest {
	Dependency a = Dependency(">=1.1.0"), b = Dependency(">=1.3.0");
	assert (a.merge(b).valid() && a.merge(b).versionString == ">=1.3.0", a.merge(b).toString());

	assertThrown(Dependency("<=2.0.0 >=1.0.0"));
	assertThrown(Dependency(">=2.0.0 <=1.0.0"));

	a = Dependency(">=1.0.0 <=5.0.0"); b = Dependency(">=2.0.0");
	assert (a.merge(b).valid() && a.merge(b).versionString == ">=2.0.0 <=5.0.0", a.merge(b).toString());

	assertThrown(a = Dependency(">1.0.0 ==5.0.0"), "Construction is invalid");

	a = Dependency(">1.0.0"); b = Dependency("<2.0.0");
	assert (a.merge(b).valid(), a.merge(b).toString());
	assert (a.merge(b).versionString == ">1.0.0 <2.0.0", a.merge(b).toString());

	a = Dependency(">2.0.0"); b = Dependency("<1.0.0");
	assert (!(a.merge(b)).valid(), a.merge(b).toString());

	a = Dependency(">=2.0.0"); b = Dependency("<=1.0.0");
	assert (!(a.merge(b)).valid(), a.merge(b).toString());

	a = Dependency("==2.0.0"); b = Dependency("==1.0.0");
	assert (!(a.merge(b)).valid(), a.merge(b).toString());

	a = Dependency("1.0.0"); b = Dependency("==1.0.0");
	assert (a == b);

	a = Dependency("<=2.0.0"); b = Dependency("==1.0.0");
	Dependency m = a.merge(b);
	assert (m.valid(), m.toString());
	assert (m.matches(Version("1.0.0")));
	assert (!m.matches(Version("1.1.0")));
	assert (!m.matches(Version("0.0.1")));


	// branches / head revisions
	a = Dependency(Version.MASTER_STRING);
	assert(a.valid());
	assert(a.matches(Version.MASTER));
	b = Dependency(Version.MASTER_STRING);
	m = a.merge(b);
	assert(m.matches(Version.MASTER));

	//assertThrown(a = Dependency(Version.MASTER_STRING ~ " <=1.0.0"), "Construction invalid");
	assertThrown(a = Dependency(">=1.0.0 " ~ Version.MASTER_STRING), "Construction invalid");

	immutable string branch1 = Version.BRANCH_IDENT ~ "Branch1";
	immutable string branch2 = Version.BRANCH_IDENT ~ "Branch2";

	//assertThrown(a = Dependency(branch1 ~ " " ~ branch2), "Error: '" ~ branch1 ~ " " ~ branch2 ~ "' succeeded");
	//assertThrown(a = Dependency(Version.MASTER_STRING ~ " " ~ branch1), "Error: '" ~ Version.MASTER_STRING ~ " " ~ branch1 ~ "' succeeded");

	a = Dependency(branch1);
	b = Dependency(branch2);
	assert(!a.merge(b).valid, "Shouldn't be able to merge to different branches");
	b = a.merge(a);
	assert(b.valid, "Should be able to merge the same branches. (?)");
	assert(a == b);

	a = Dependency(branch1);
	assert(a.matches(branch1), "Dependency(branch1) does not match 'branch1'");
	assert(a.matches(Version(branch1)), "Dependency(branch1) does not match Version('branch1')");
	assert(!a.matches(Version.MASTER), "Dependency(branch1) matches Version.MASTER");
	assert(!a.matches(branch2), "Dependency(branch1) matches 'branch2'");
	assert(!a.matches(Version("1.0.0")), "Dependency(branch1) matches '1.0.0'");
	a = Dependency(">=1.0.0");
	assert(!a.matches(Version(branch1)), "Dependency(1.0.0) matches 'branch1'");

	// Testing optional dependencies.
	a = Dependency(">=1.0.0");
	assert(!a.optional, "Default is not optional.");
	b = a;
	assert(!a.merge(b).optional, "Merging two not optional dependencies wrong.");
	a.optional = true;
	assert(!a.merge(b).optional, "Merging optional with not optional wrong.");
	b.optional = true;
	assert(a.merge(b).optional, "Merging two optional dependencies wrong.");

	// SemVer's sub identifiers.
	a = Dependency(">=1.0.0-beta");
	assert(!a.matches(Version("1.0.0-alpha")), "Failed: match 1.0.0-alpha with >=1.0.0-beta");
	assert(a.matches(Version("1.0.0-beta")), "Failed: match 1.0.0-beta with >=1.0.0-beta");
	assert(a.matches(Version("1.0.0")), "Failed: match 1.0.0 with >=1.0.0-beta");
	assert(a.matches(Version("1.0.0-rc")), "Failed: match 1.0.0-rc with >=1.0.0-beta");

	// Approximate versions.
	a = Dependency("~>3.0");
	b = Dependency(">=3.0.0 <4.0.0");
	assert(a == b, "Testing failed: " ~ a.toString());
	assert(a.matches(Version("3.1.146")), "Failed: Match 3.1.146 with ~>0.1.2");
	assert(!a.matches(Version("0.2.0")), "Failed: Match 0.2.0 with ~>0.1.2");
	a = Dependency("~>3.0.0");
	assert(a == Dependency(">=3.0.0 <3.1.0"), "Testing failed: " ~ a.toString());
	a = Dependency("~>3.5");
	assert(a == Dependency(">=3.5.0 <4.0.0"), "Testing failed: " ~ a.toString());
	a = Dependency("~>3.5.0");
	assert(a == Dependency(">=3.5.0 <3.6.0"), "Testing failed: " ~ a.toString());

	a = Dependency("~>0.1.1");
	b = Dependency("==0.1.0");
	assert(!a.merge(b).valid);
	b = Dependency("==0.1.9999");
	assert(a.merge(b).valid);
	b = Dependency("==0.2.0");
	assert(!a.merge(b).valid);

	a = Dependency("~>1.0.1-beta");
	b = Dependency(">=1.0.1-beta <1.1.0");
	assert(a == b, "Testing failed: " ~ a.toString());
	assert(a.matches(Version("1.0.1-beta")));
	assert(a.matches(Version("1.0.1-beta.6")));

	a = Dependency("~d2test");
	assert(!a.optional);
	assert(a.valid);
	assert(a.version_ == Version("~d2test"));

	a = Dependency("==~d2test");
	assert(!a.optional);
	assert(a.valid);
	assert(a.version_ == Version("~d2test"));

	a = Dependency.ANY;
	assert(!a.optional);
	assert(a.valid);
	assertThrown(a.version_);
	b = Dependency(">=1.0.1");
	assert(b == a.merge(b));
	assert(b == b.merge(a));

	assert(Dependency.any.toString() == "*");
	assert(Dependency("==1.0.0").toString() == "1.0.0");
	assert(Dependency("1.0.0").toString() == "1.0.0");
	assert(Dependency("~master").toString() == "~master");
	assert(Dependency("~branch").toString() == "~branch");
	assert(Dependency("*").toString() == "*");
	assert(Dependency(">1.0.0").toString() == ">1.0.0");
	assert(Dependency(">=1.0.0").toString() == ">=1.0.0");
	assert(Dependency("<=1.0.0").toString() == "<=1.0.0");
	assert(Dependency("<1.0.0").toString() == "<1.0.0");
	assert(Dependency(">1.0.0 <2.0.0").toString() == ">1.0.0 <2.0.0");
	assert(Dependency(">=1.0.0 <2.0.0").toString() == ">=1.0.0 <2.0.0");
	assert(Dependency(">1.0.0 <=2.0.0").toString() == ">1.0.0 <=2.0.0");
	assert(Dependency(">=1.0.0 <=2.0.0").toString() == ">=1.0.0 <=2.0.0");
}


/**
	A version in the format "major.update.bugfix-prerelease+buildmetadata"
	according to Semantic Versioning Specification v2.0.0.

	(deprecated):
	This also supports a format like "~master", to identify trunk, or
	"~branch_name" to identify a branch. Both Version types starting with "~"
	refer to the head revision of the corresponding branch.
	This is subject to be removed soon.
*/
struct Version {
	private {
		enum MAX_VERS = "99999.0.0";
		enum UNKNOWN_VERS = "unknown";
		string m_version = "0.0.0";
	}

	static @property RELEASE() { return Version("0.0.0"); }
	static @property HEAD() { return Version(MAX_VERS); }
	static @property MASTER() { return Version(MASTER_STRING); }
	static @property UNKNOWN() { return Version(UNKNOWN_VERS); }
	static @property MASTER_STRING() { return "~master"; }
	static @property BRANCH_IDENT() { return '~'; }

	this(string vers)
	{
		enforce(vers.length > 1, "Version strings must not be empty.");
		if (vers[0] != BRANCH_IDENT && vers != UNKNOWN_VERS)
			enforce(vers.isValidVersion(), "Invalid SemVer format: " ~ vers);
		m_version = vers;
	}

	static Version fromString(string vers) { return Version(vers); }

	bool opEquals(const Version oth) const {
		if (isUnknown || oth.isUnknown) {
			throw new Exception("Can't compare unknown versions! (this: %s, other: %s)".format(this, oth));
		}
		return opCmp(oth) == 0;
	}

	/// Returns true, if this version indicates a branch, which is not the trunk.
	@property bool isBranch() const { return !m_version.empty && m_version[0] == BRANCH_IDENT; }
	@property bool isMaster() const { return m_version == MASTER_STRING; }
	@property bool isPreRelease() const {
		if (isBranch) return true;
		return isPreReleaseVersion(m_version);
	}
	@property bool isUnknown() const { return m_version == UNKNOWN_VERS; }

	/**
		Comparing Versions is generally possible, but comparing Versions
		identifying branches other than master will fail. Only equality
		can be tested for these.
	*/
	int opCmp(ref const Version other)
	const {
		if (isUnknown || other.isUnknown) {
			throw new Exception("Can't compare unknown versions! (this: %s, other: %s)".format(this, other));
		}
		if (isBranch || other.isBranch) {
			if(m_version == other.m_version) return 0;
			if (!isBranch) return 1;
			else if (!other.isBranch) return -1;
			if (isMaster) return 1;
			else if (other.isMaster) return -1;
			return this.m_version < other.m_version ? -1 : 1;
		}

		return compareVersions(isMaster ? MAX_VERS : m_version, other.isMaster ? MAX_VERS : other.m_version);
	}
	int opCmp(in Version other) const { return opCmp(other); }

	string toString() const { return m_version; }
}

unittest {
	Version a, b;

	assertNotThrown(a = Version("1.0.0"), "Constructing Version('1.0.0') failed");
	assert(!a.isBranch, "Error: '1.0.0' treated as branch");
	assert(a == a, "a == a failed");

	assertNotThrown(a = Version(Version.MASTER_STRING), "Constructing Version("~Version.MASTER_STRING~"') failed");
	assert(a.isBranch, "Error: '"~Version.MASTER_STRING~"' treated as branch");
	assert(a.isMaster);
	assert(a == Version.MASTER, "Constructed master version != default master version.");

	assertNotThrown(a = Version("~BRANCH"), "Construction of branch Version failed.");
	assert(a.isBranch, "Error: '~BRANCH' not treated as branch'");
	assert(!a.isMaster);
	assert(a == a, "a == a with branch failed");

	// opCmp
	a = Version("1.0.0");
	b = Version("1.0.0");
	assert(a == b, "a == b with a:'1.0.0', b:'1.0.0' failed");
	b = Version("2.0.0");
	assert(a != b, "a != b with a:'1.0.0', b:'2.0.0' failed");
	a = Version(Version.MASTER_STRING);
	b = Version("~BRANCH");
	assert(a != b, "a != b with a:MASTER, b:'~branch' failed");
	assert(a > b);
	assert(a < Version("0.0.0"));
	assert(b < Version("0.0.0"));
	assert(a > Version("~Z"));
	assert(b < Version("~Z"));

	// SemVer 2.0.0-rc.2
	a = Version("2.0.0-rc.2");
	b = Version("2.0.0-rc.3");
	assert(a < b, "Failed: 2.0.0-rc.2 < 2.0.0-rc.3");

	a = Version("2.0.0-rc.2+build-metadata");
	b = Version("2.0.0+build-metadata");
	assert(a < b, "Failed: "~a.toString()~"<"~b.toString());

	// 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0
	Version[] versions;
	versions ~= Version("1.0.0-alpha");
	versions ~= Version("1.0.0-alpha.1");
	versions ~= Version("1.0.0-beta.2");
	versions ~= Version("1.0.0-beta.11");
	versions ~= Version("1.0.0-rc.1");
	versions ~= Version("1.0.0");
	for(int i=1; i<versions.length; ++i)
		for(int j=i-1; j>=0; --j)
			assert(versions[j] < versions[i], "Failed: " ~ versions[j].toString() ~ "<" ~ versions[i].toString());

	a = Version.UNKNOWN;
	b = Version.RELEASE;
	assertThrown(a == b, "Failed: compared " ~ a.toString() ~ " with " ~ b.toString() ~ "");

	a = Version.UNKNOWN;
	b = Version.UNKNOWN;
	assertThrown(a == b, "Failed: UNKNOWN == UNKNOWN");

	assert(Version("1.0.0+a") == Version("1.0.0+b"));
	assert(Version() <= Version());
}


/// Represents a generic mathematical interval
private struct Interval(T)
{
	static assert(Interval.init.empty);

	private {
		T m_min;
		T m_max;
		bool m_minInclusive = false;
		bool m_maxInclusive = false;
	}

	this(T min, T max, string bounds = "[)")
		in {
			assert(min <= max, format("Minumum must be lower or equal to the maximum value: %s !<= %s", min, max));
			assert(bounds.length == 2 && "[(".canFind(bounds[0]) && "])".canFind(bounds[1]),
				"Bounds must be a string composed of round and square brackets.");
		}
	body {

		m_min = min;
		m_max = max;
		m_minInclusive = bounds[0] == '[';
		m_maxInclusive = bounds[1] == ']';
	}

	// BUG: 1 < x < 2 is also empty for integers!!
	@property bool empty() const {
		if (m_min > m_max) return true;
		if (m_min < m_max) return false;
		return !m_minInclusive || !m_maxInclusive;
	}

	/// True iff `min` equals `max` and both ends of the interval are inclusive.
	@property bool singular() const { return m_min == m_max && m_minInclusive && m_maxInclusive; }

	@property inout(T) min() inout { return m_min; }
	@property inout(T) max() inout { return m_max; }
	@property bool minInclusive() const { return m_minInclusive; }
	@property bool maxInclusive() const { return m_maxInclusive; }

	bool contains(T value)
	const {
		if (!m_minInclusive && value <= m_min) return false;
		if (value < m_min) return false;

		if (!m_maxInclusive && value >= m_max) return false;
		if (value > m_max) return false;

		return true;
	}

	bool opEquals(Interval other)
	const {
		if (m_min == other.m_min && m_max == other.m_max && m_minInclusive == other.m_minInclusive && m_maxInclusive == other.m_maxInclusive)
			return true;
		// BUG: integral ranges [1, 10] and (0, 11) are equal in a strict sense!
		return false;
	}

	int opCmp(in Interval o)
	const {
		if (m_minInclusive != o.m_minInclusive) return m_minInclusive < o.m_minInclusive ? -1 : 1;
		if (m_maxInclusive != o.m_maxInclusive) return m_maxInclusive < o.m_maxInclusive ? -1 : 1;
		if (m_min != o.m_min) return m_min < o.m_min ? -1 : 1;
		if (m_max != o.m_max) return m_max < o.m_max ? -1 : 1;
		return 0;
	}

	Interval opBinary(string op)(Interval other) const if (op == "&")
	{
		Interval ret;

		if (this.m_min > other.m_min) {
			ret.m_min = this.m_min;
			ret.m_minInclusive = this.m_minInclusive;
		} else if (other.m_min > this.m_min) {
			ret.m_min = other.m_min;
			ret.m_minInclusive = other.m_minInclusive;
		} else {
			ret.m_min = this.m_min;
			ret.m_minInclusive = this.m_minInclusive && other.m_minInclusive;
		}

		if (this.max < other.max) {
			ret.m_max = this.m_max;
			ret.m_maxInclusive = this.m_maxInclusive;
		} else if (other.m_max < this.m_max) {
			ret.m_max = other.m_max;
			ret.m_maxInclusive = other.m_maxInclusive;
		} else {
			ret.m_max = this.m_max;
			ret.m_maxInclusive = this.m_maxInclusive && other.m_maxInclusive;
		}

		return ret;
	}

	Interval opBinary(string op)(Interval other) const if (op == "|")
	{
		Interval ret;

		if (this.m_min < other.m_min) {
			ret.m_min = this.m_min;
			ret.m_minInclusive = this.m_minInclusive;
		} else if (other.m_min < this.m_min) {
			ret.m_min = other.m_min;
			ret.m_minInclusive = other.m_minInclusive;
		} else {
			ret.m_min = this.m_min;
			ret.m_minInclusive = this.m_minInclusive || other.m_minInclusive;
		}

		if (this.max > other.max) {
			ret.m_max = this.m_max;
			ret.m_maxInclusive = this.m_maxInclusive;
		} else if (other.m_max > this.m_max) {
			ret.m_max = other.m_max;
			ret.m_maxInclusive = other.m_maxInclusive;
		} else {
			ret.m_max = this.m_max;
			ret.m_maxInclusive = this.m_maxInclusive || other.m_maxInclusive;
		}

		if (ret.m_min > ret.m_max) return Interval.init;

		return ret;
	}
}

unittest {
	alias Inti = Interval!int;

	assert(!Inti(-1, 1).contains(-2));
	assert(Inti(-1, 1).contains(-1));
	assert(Inti(-1, 1).contains(0));
	assert(!Inti(-1, 1).contains(1));
	assert(!Inti(-1, 1).contains(2));

	assert(!Inti(-1, 1, "[]").contains(-2));
	assert(Inti(-1, 1, "[]").contains(-1));
	assert(Inti(-1, 1, "[]").contains(0));
	assert(Inti(-1, 1, "[]").contains(1));
	assert(!Inti(-1, 1, "[]").contains(2));

	assert(!Inti(-1, 1, "()").contains(-2));
	assert(!Inti(-1, 1, "()").contains(-1));
	assert(Inti(-1, 1, "()").contains(0));
	assert(!Inti(-1, 1, "()").contains(1));
	assert(!Inti(-1, 1, "()").contains(2));

	assert((Inti(1, 10, "[]") | Inti(1, 10, "()")) == Inti(1, 10, "[]"));
	assert((Inti(1, 10, "[]") & Inti(1, 10, "()")) == Inti(1, 10, "()"));
	assert((Inti(1, 10, "()") | Inti(1, 10, "[]")) == Inti(1, 10, "[]"));
	assert((Inti(1, 10, "()") & Inti(1, 10, "[]")) == Inti(1, 10, "()"));

	assert((Inti(1, 10, "[]") | Inti(2, 11, "()")) == Inti(1, 11, "[)"));
	assert((Inti(1, 10, "[]") & Inti(2, 11, "()")) == Inti(2, 10, "(]"));
	assert((Inti(2, 11, "()") | Inti(1, 10, "[]")) == Inti(1, 11, "[)"));
	assert((Inti(2, 11, "()") & Inti(1, 10, "[]")) == Inti(2, 10, "(]"));

	assert(Inti(0, 1) == Inti(0, 1, "[)"));
	assert(Inti(0, 1) != Inti(0, 1, "[]"));
	assert(Inti(0, 1) != Inti(0, 1, "()"));
	assert(Inti(0, 1) != Inti(0, 1, "(]"));

	assert(!Inti(0, 1).empty);
	assert(Inti(0, 0).empty);

	// failing integer unit tests:
	//assert(Inti(0, 1, "()").empty);
	//assert(Inti(0, 1, "[)") == Inti(0, 0, "[]"));
}
