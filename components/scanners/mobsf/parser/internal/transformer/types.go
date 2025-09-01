package transformer

import "time"

// CommonReport contains fields shared by both AndroidReport and IOsReport.
type CommonReport struct {
	AppName    string        `json:"app_name"`
	AppType    string        `json:"app_type"`
	FileName   string        `json:"file_name"`
	Files      []string      `json:"files"`
	HostOs     string        `json:"host_os"`
	IconPath   string        `json:"icon_path"`
	Libraries  []string      `json:"libraries"`
	Logs       []Log         `json:"logs"`
	Md5        string        `json:"md5"`
	Sha1       string        `json:"sha1"`
	Sha256     string        `json:"sha256"`
	Size       string        `json:"size"`
	Secrets    []interface{} `json:"secrets"`
	Strings    interface{}   `json:"strings"`
	Timestamp  time.Time     `json:"timestamp"`
	Title      string        `json:"title"`
	Trackers   Trackers      `json:"trackers"`
	Urls       []Url         `json:"urls"`
	Version    string        `json:"version"`
	VirusTotal interface{}   `json:"virus_total"`
	Domains    Domains       `json:"domains"`
}

// AndroidReport embeds CommonReport and adds Android-specific fields.
type AndroidReport struct {
	CommonReport
	Activities []string `json:"activities"`
	// Apkid               Apkid               `json:"apkid"` // unused
	Appsec      Appsec      `json:"appsec"`
	AverageCvss interface{} `json:"average_cvss"`
	// BaseURL             string              `json:"base_url"` // unused
	// Behaviour           Behaviour           `json:"behaviour"` // unused
	BinaryAnalysis      []BinaryAnalysis    `json:"binary_analysis"`
	BrowsableActivities BrowsableActivities `json:"browsable_activities"`
	CertificateAnalysis CertificateAnalysis `json:"certificate_analysis"`
	CodeAnalysis        CodeAnalysis        `json:"code_analysis"`
	DwdDir              string              `json:"dwd_dir"`
	Emails              []Email             `json:"emails"`
	ExportedActivities  string              `json:"exported_activities"`
	ExportedCount       ExportedCount       `json:"exported_count"`
	FileAnalysis        []interface{}       `json:"file_analysis"`
	FirebaseUrls        []FirebaseUrl       `json:"firebase_urls"`
	MainActivity        string              `json:"main_activity"`
	MalwarePermissions  MalwarePermissions  `json:"malware_permissions"`
	ManifestAnalysis    ManifestAnalysis    `json:"manifest_analysis"`
	MaxSdk              string              `json:"max_sdk"`
	MinSdk              string              `json:"min_sdk"`
	NetworkSecurity     NetworkSecurity     `json:"network_security"`
	NiapAnalysis        NiapAnalysis        `json:"niap_analysis"`
	PackageName         string              `json:"package_name"`
	PermissionMapping   PermissionMapping   `json:"permission_mapping"`
	Permissions         Permissions         `json:"permissions"`
	PlaystoreDetails    PlaystoreDetails    `json:"playstore_details"`
	Providers           []string            `json:"providers"`
	Receivers           []string            `json:"receivers"`
	Sbom                Sbom                `json:"sbom"`
	Services            []string            `json:"services"`
	// Strings             Strings             `json:"strings"` // Android-specific -- currently not parsed
	TargetSdk   string `json:"target_sdk"`
	VersionCode string `json:"version_code"`
	VersionName string `json:"version_name"`
}

// IOsReport embeds CommonReport and adds iOS-specific fields.
type IOsReport struct {
	CommonReport
	Appsec                   Appsec            `json:"appsec"`
	AppstoreDetails          AppstoreDetails   `json:"appstore_details"`
	AtsAnalysis              AtsAnalysis       `json:"ats_analysis"`
	AverageCvss              interface{}       `json:"average_cvss"`
	BaseURL                  string            `json:"base_url"`
	BinaryAnalysis           IosBinaryAnalysis `json:"binary_analysis"`
	BinaryInfo               BinaryInfo        `json:"binary_info"`
	Build                    string            `json:"build"`
	BundleID                 string            `json:"bundle_id"`
	BundleSupportedPlatforms []string          `json:"bundle_supported_platforms"`
	BundleURLTypes           []BundleURLType   `json:"bundle_url_types"`
	CodeAnalysis             CodeAnalysis      `json:"code_analysis"`
	DwdDir                   string            `json:"dwd_dir"`
	DylibAnalysis            []IosLibAnalysis  `json:"dylib_analysis"`
	Emails                   []Email           `json:"emails"`
	FileAnalysis             []IosFileAnalysis `json:"file_analysis"`
	FirebaseUrls             []interface{}     `json:"firebase_urls"`
	FrameworkAnalysis        []IosLibAnalysis  `json:"framework_analysis"`
	InfoPlist                string            `json:"info_plist"`
	IosAPI                   IosAPI            `json:"ios_api"`
	MachoAnalysis            IosLibAnalysis    `json:"macho_analysis"`
	MinOsVersion             string            `json:"min_os_version"`
	Permissions              IosPermissions    `json:"permissions"`
	Platform                 string            `json:"platform"`
	SdkName                  string            `json:"sdk_name"`
	Trackers                 IosTrackers       `json:"trackers"`
}

type AppstoreDetails struct {
	Error bool `json:"error"`
}

type AtsAnalysis struct {
	AtsFindings []AtsFinding `json:"ats_findings"`
	AtsSummary  AtsSummary   `json:"ats_summary"`
}

type AtsFinding struct {
	Description string `json:"description"`
	Issue       string `json:"issue"`
	Severity    string `json:"severity"`
}

type AtsSummary struct {
	High    int `json:"high"`
	Info    int `json:"info"`
	Secure  int `json:"secure"`
	Warning int `json:"warning"`
}

type IosBinaryAnalysis struct {
	Findings map[string]IosBinaryFinding `json:"findings"`
	Summary  CodeSummary                 `json:"summary"`
}

type IosBinaryFinding struct {
	Cvss         float64 `json:"cvss"`
	Cwe          string  `json:"cwe"`
	DetailedDesc string  `json:"detailed_desc"`
	Masvs        string  `json:"masvs"`
	OwaspMobile  string  `json:"owasp-mobile"`
	Severity     string  `json:"severity"`
}

type BinaryInfo struct {
	Arch    string `json:"arch"`
	Bit     string `json:"bit"`
	Endian  string `json:"endian"`
	Subarch string `json:"subarch"`
}

type BundleURLType struct {
	CFBundleURLName    string   `json:"CFBundleURLName"`
	CFBundleURLSchemes []string `json:"CFBundleURLSchemes"`
}

type IosLibAnalysis struct {
	Arc           IosArc           `json:"arc"`
	CodeSignature IosCodeSignature `json:"code_signature"`
	Encrypted     IosEncrypted     `json:"encrypted"`
	Name          string           `json:"name"`
	Nx            IosNx            `json:"nx"`
	Pie           IosPie           `json:"pie"`
	Rpath         IosRpath         `json:"rpath"`
	StackCanary   IosStackCanary   `json:"stack_canary"`
	Symbol        IosSymbol        `json:"symbol"`
}

type IosArc struct {
	Description string `json:"description"`
	HasArc      bool   `json:"has_arc"`
	Severity    string `json:"severity"`
}

type IosCodeSignature struct {
	Description      string `json:"description"`
	HasCodeSignature bool   `json:"has_code_signature"`
	Severity         string `json:"severity"`
}

type IosEncrypted struct {
	Description string `json:"description"`
	IsEncrypted bool   `json:"is_encrypted"`
	Severity    string `json:"severity"`
}

type IosNx struct {
	Description string `json:"description"`
	HasNx       bool   `json:"has_nx"`
	Severity    string `json:"severity"`
}

type IosPie struct {
	Description string `json:"description"`
	HasPie      bool   `json:"has_pie"`
	Severity    string `json:"severity"`
}

type IosRpath struct {
	Description string `json:"description"`
	HasRpath    bool   `json:"has_rpath"`
	Severity    string `json:"severity"`
}

type IosStackCanary struct {
	Description string `json:"description"`
	HasCanary   bool   `json:"has_canary"`
	Severity    string `json:"severity"`
}

type IosSymbol struct {
	Description string `json:"description"`
	IsStripped  bool   `json:"is_stripped"`
	Severity    string `json:"severity"`
}

type IosFileAnalysis struct {
	Files []IosFile `json:"files"`
	Issue string    `json:"issue"`
}

type IosFile struct {
	FilePath string `json:"file_path"`
	Hash     string `json:"hash"`
	Type     string `json:"type"`
}

type IosAPI struct{}

type IosPermissions struct {
	NSCameraUsageDescription PermissionDetail `json:"NSCameraUsageDescription"`
}

type IosTrackers struct {
	DetectedTrackers int          `json:"detected_trackers"`
	TotalTrackers    int          `json:"total_trackers"`
	Trackers         []IosTracker `json:"trackers"`
}

type IosTracker struct {
	Categories string `json:"categories"`
	Name       string `json:"name"`
	URL        string `json:"url"`
}

type Apkid struct {
	ClassesDex ClassesDex `json:"classes.dex"`
}

type ClassesDex struct {
	AntiVM   []string `json:"anti_vm"`
	Compiler []string `json:"compiler"`
}

type Appsec struct {
	AppName       string    `json:"app_name"`
	FileName      string    `json:"file_name"`
	Hash          string    `json:"hash"`
	High          []Finding `json:"high"`
	Warning       []Finding `json:"warning"`
	Info          []Finding `json:"info"`
	Secure        []Finding `json:"secure"`
	Hotspot       []Finding `json:"hotspot"`
	SecurityScore int       `json:"security_score"`
	TotalTrackers int       `json:"total_trackers"`
	Trackers      int       `json:"trackers"`
	VersionName   string    `json:"version_name"`
}

type Finding struct {
	Description string `json:"description"`
	Section     string `json:"section"`
	Title       string `json:"title"`
}

type Behaviour struct {
	Num00012 BehaviourItem `json:"00012"`
	Num00013 BehaviourItem `json:"00013"`
	Num00022 BehaviourItem `json:"00022"`
	Num00028 BehaviourItem `json:"00028"`
	Num00051 BehaviourItem `json:"00051"`
	Num00063 BehaviourItem `json:"00063"`
	Num00089 BehaviourItem `json:"00089"`
	Num00091 BehaviourItem `json:"00091"`
	Num00096 BehaviourItem `json:"00096"`
	Num00109 BehaviourItem `json:"00109"`
	Num00153 BehaviourItem `json:"00153"`
	Num00161 BehaviourItem `json:"00161"`
	Num00173 BehaviourItem `json:"00173"`
	Num00209 BehaviourItem `json:"00209"`
	Num00210 BehaviourItem `json:"00210"`
}

type BehaviourItem struct {
	Files    map[string]string `json:"files"`
	Metadata BehaviourMetadata `json:"metadata"`
}

type BehaviourMetadata struct {
	Description string   `json:"description"`
	Label       []string `json:"label"`
	Severity    string   `json:"severity"`
}

// BinaryAnalysis is a struct representing the binary analysis section of the MobSF report.
// It contains information about the security features of the binary.
// the fields in this struct are hardcoded in the MOBSF report upstream
type BinaryAnalysis struct {
	Fortify            Fortify            `json:"fortify"`
	Name               string             `json:"name"`
	Nx                 Nx                 `json:"nx"`
	Pie                Pie                `json:"pie"`
	RelocationReadonly RelocationReadonly `json:"relocation_readonly"`
	Rpath              Rpath              `json:"rpath"`
	Runpath            Runpath            `json:"runpath"`
	StackCanary        StackCanary        `json:"stack_canary"`
	Symbol             Symbol             `json:"symbol"`
}

type Fortify struct {
	Description string `json:"description"`
	IsFortified bool   `json:"is_fortified"`
	Severity    string `json:"severity"`
}

type Nx struct {
	Description string `json:"description"`
	IsNx        bool   `json:"is_nx"`
	Severity    string `json:"severity"`
}

type Pie struct {
	Description string `json:"description"`
	IsPie       string `json:"is_pie"`
	Severity    string `json:"severity"`
}

type RelocationReadonly struct {
	Description string `json:"description"`
	Relro       string `json:"relro"`
	Severity    string `json:"severity"`
}

type Rpath struct {
	Description string      `json:"description"`
	Rpath       interface{} `json:"rpath"`
	Severity    string      `json:"severity"`
}

type Runpath struct {
	Description string      `json:"description"`
	Runpath     interface{} `json:"runpath"`
	Severity    string      `json:"severity"`
}

type StackCanary struct {
	Description string `json:"description"`
	HasCanary   bool   `json:"has_canary"`
	Severity    string `json:"severity"`
}

type Symbol struct {
	Description string `json:"description"`
	IsStripped  bool   `json:"is_stripped"`
	Severity    string `json:"severity"`
}

type BrowsableActivities struct {
	B3NacInjuredandroidCSPBypassActivity BrowsableActivity `json:"b3nac.injuredandroid.CSPBypassActivity"`
	B3NacInjuredandroidDeepLinkActivity  BrowsableActivity `json:"b3nac.injuredandroid.DeepLinkActivity"`
	B3NacInjuredandroidRCEActivity       BrowsableActivity `json:"b3nac.injuredandroid.RCEActivity"`
}

type BrowsableActivity struct {
	Browsable    bool          `json:"browsable"`
	Hosts        []string      `json:"hosts"`
	MimeTypes    []interface{} `json:"mime_types"`
	PathPatterns []string      `json:"path_patterns"`
	PathPrefixs  []interface{} `json:"path_prefixs"`
	Paths        []interface{} `json:"paths"`
	Ports        []interface{} `json:"ports"`
	Schemes      []string      `json:"schemes"`
	WellKnown    WellKnown     `json:"well_known"`
}

type WellKnown struct {
	HTTPB3NacComWellKnownAssetlinksJSON  string `json:"http://b3nac.com/.well-known/assetlinks.json"`
	HTTPSB3NacComWellKnownAssetlinksJSON string `json:"https://b3nac.com/.well-known/assetlinks.json"`
}

type CertificateAnalysis struct {
	CertificateFindings [][]string         `json:"certificate_findings"`
	CertificateInfo     string             `json:"certificate_info"`
	CertificateSummary  CertificateSummary `json:"certificate_summary"`
}

type CertificateSummary struct {
	High    int `json:"high"`
	Info    int `json:"info"`
	Warning int `json:"warning"`
}

type CodeAnalysis struct {
	Findings map[string]CodeFinding `json:"findings"`
	Summary  CodeSummary            `json:"summary"`
}

type CodeFinding struct {
	Files    map[string]string      `json:"files"`
	Metadata AndroidFindingMetadata `json:"metadata"`
}

type AndroidFindingMetadata struct {
	Cvss        float64 `json:"cvss"`
	Cwe         string  `json:"cwe"`
	Description string  `json:"description"`
	Masvs       string  `json:"masvs"`
	OwaspMobile string  `json:"owasp-mobile"`
	Ref         string  `json:"ref"`
	Severity    string  `json:"severity"`
}

type CodeSummary struct {
	High       int `json:"high"`
	Info       int `json:"info"`
	Secure     int `json:"secure"`
	Suppressed int `json:"suppressed"`
	Warning    int `json:"warning"`
}

type Domains struct {
	DeveloperAndroidCom         Domain `json:"developer.android.com"`
	GithubCom                   Domain `json:"github.com"`
	InjuredandroidFirebaseioCom Domain `json:"injuredandroid.firebaseio.com"`
	MDoCo                       Domain `json:"m.do.co"`
	WwwW3Org                    Domain `json:"www.w3.org"`
}

type Domain struct {
	Bad         string      `json:"bad"`
	Geolocation Geolocation `json:"geolocation"`
	Ofac        bool        `json:"ofac"`
}

type Geolocation struct {
	City         string `json:"city"`
	CountryLong  string `json:"country_long"`
	CountryShort string `json:"country_short"`
	IP           string `json:"ip"`
	Latitude     string `json:"latitude"`
	Longitude    string `json:"longitude"`
	Region       string `json:"region"`
}

type Email struct {
	Emails []string `json:"emails"`
	Path   string   `json:"path"`
}

type ExportedCount struct {
	ExportedActivities int `json:"exported_activities"`
	ExportedProviders  int `json:"exported_providers"`
	ExportedReceivers  int `json:"exported_receivers"`
	ExportedServices   int `json:"exported_services"`
}

type FirebaseUrl struct {
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
}

type Log struct {
	Exception interface{} `json:"exception"`
	Status    string      `json:"status"`
	Timestamp string      `json:"timestamp"`
}

type MalwarePermissions struct {
	OtherAbusedPermissions  []interface{} `json:"other_abused_permissions"`
	TopMalwarePermissions   []string      `json:"top_malware_permissions"`
	TotalMalwarePermissions int           `json:"total_malware_permissions"`
	TotalOtherPermissions   int           `json:"total_other_permissions"`
}

type ManifestAnalysis struct {
	ManifestFindings []ManifestFinding `json:"manifest_findings"`
	ManifestSummary  ManifestSummary   `json:"manifest_summary"`
}

type ManifestFinding struct {
	Component   []string `json:"component"`
	Description string   `json:"description"`
	Name        string   `json:"name"`
	Rule        string   `json:"rule"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
}

type ManifestSummary struct {
	High       int `json:"high"`
	Info       int `json:"info"`
	Suppressed int `json:"suppressed"`
	Warning    int `json:"warning"`
}

type NetworkSecurity struct {
	NetworkFindings []NetworkFinding `json:"network_findings"`
	NetworkSummary  NetworkSummary   `json:"network_summary"`
}

type NetworkFinding struct {
	Description string   `json:"description"`
	Scope       []string `json:"scope"`
	Severity    string   `json:"severity"`
}

type NetworkSummary struct {
	High    int `json:"high"`
	Info    int `json:"info"`
	Secure  int `json:"secure"`
	Warning int `json:"warning"`
}

type NiapAnalysis struct{}

type PermissionMapping struct {
	AndroidPermissionINTERNET             PermissionFiles `json:"android.permission.INTERNET"`
	AndroidPermissionREADEXTERNALSTORAGE  PermissionFiles `json:"android.permission.READ_EXTERNAL_STORAGE"`
	AndroidPermissionWRITEEXTERNALSTORAGE PermissionFiles `json:"android.permission.WRITE_EXTERNAL_STORAGE"`
}

type PermissionFiles struct {
	BAAVAJava                          string `json:"b/a/a/v/a.java"`
	BAAVFJava                          string `json:"b/a/a/v/f.java"`
	BAAVJJava                          string `json:"b/a/a/v/j.java"`
	BDAAAJava                          string `json:"b/d/a/a/a.java"`
	AGDEJava                           string `json:"a/g/d/e.java"`
	AGDKJava                           string `json:"a/g/d/k.java"`
	BAAVEJava                          string `json:"b/a/a/v/e.java"`
	B3NacInjuredandroidRCEActivityJava string `json:"b3nac/injuredandroid/RCEActivity.java"`
}

type Permissions struct {
	AndroidPermissionACCESSNETWORKSTATE   PermissionDetail `json:"android.permission.ACCESS_NETWORK_STATE"`
	AndroidPermissionINTERNET             PermissionDetail `json:"android.permission.INTERNET"`
	AndroidPermissionREADEXTERNALSTORAGE  PermissionDetail `json:"android.permission.READ_EXTERNAL_STORAGE"`
	AndroidPermissionREADPHONESTATE       PermissionDetail `json:"android.permission.READ_PHONE_STATE"`
	AndroidPermissionWRITEEXTERNALSTORAGE PermissionDetail `json:"android.permission.WRITE_EXTERNAL_STORAGE"`
}

type PermissionDetail struct {
	Description string `json:"description"`
	Info        string `json:"info"`
	Status      string `json:"status"`
}

type PlaystoreDetails struct {
	Error bool `json:"error"`
}

type Sbom struct {
	SbomPackages  []string `json:"sbom_packages"`
	SbomVersioned []string `json:"sbom_versioned"`
}

type Strings struct {
	StringsApkRes interface{} `json:"strings_apk_res"`
	StringsCode   []string    `json:"strings_code"`
	StringsSo     []StringsSo `json:"strings_so"`
}

type StringsSo struct {
	LibArm64V8ALibappSo                   []string `json:"lib/arm64-v8a/libapp.so,omitempty"`
	LibArm64V8ALibencryptSo               []string `json:"lib/arm64-v8a/libencrypt.so,omitempty"`
	LibArm64V8ALibnativeLibSo             []string `json:"lib/arm64-v8a/libnative-lib.so,omitempty"`
	LibArm64V8ALibflutterSo               []string `json:"lib/arm64-v8a/libflutter.so,omitempty"`
	LibArmeabiV7ALibappSo                 []string `json:"lib/armeabi-v7a/libapp.so,omitempty"`
	LibArmeabiV7ALibencryptSo             []string `json:"lib/armeabi-v7a/libencrypt.so,omitempty"`
	LibArmeabiV7ALibnativeLibSo           []string `json:"lib/armeabi-v7a/libnative-lib.so,omitempty"`
	LibArmeabiV7ALibflutterSo             []string `json:"lib/armeabi-v7a/libflutter.so,omitempty"`
	LibX8664LibappSo                      []string `json:"lib/x86_64/libapp.so,omitempty"`
	LibX8664LibencryptSo                  []string `json:"lib/x86_64/libencrypt.so,omitempty"`
	LibX8664LibnativeLibSo                []string `json:"lib/x86_64/libnative-lib.so,omitempty"`
	LibX8664LibflutterSo                  []string `json:"lib/x86_64/libflutter.so,omitempty"`
	ApktoolOutLibArm64V8ALibappSo         []string `json:"apktool_out/lib/arm64-v8a/libapp.so,omitempty"`
	ApktoolOutLibArm64V8ALibencryptSo     []string `json:"apktool_out/lib/arm64-v8a/libencrypt.so,omitempty"`
	ApktoolOutLibArm64V8ALibnativeLibSo   []string `json:"apktool_out/lib/arm64-v8a/libnative-lib.so,omitempty"`
	ApktoolOutLibArm64V8ALibflutterSo     []string `json:"apktool_out/lib/arm64-v8a/libflutter.so,omitempty"`
	ApktoolOutLibArmeabiV7ALibappSo       []string `json:"apktool_out/lib/armeabi-v7a/libapp.so,omitempty"`
	ApktoolOutLibArmeabiV7ALibencryptSo   []string `json:"apktool_out/lib/armeabi-v7a/libencrypt.so,omitempty"`
	ApktoolOutLibArmeabiV7ALibnativeLibSo []string `json:"apktool_out/lib/armeabi-v7a/libnative-lib.so,omitempty"`
	ApktoolOutLibArmeabiV7ALibflutterSo   []string `json:"apktool_out/lib/armeabi-v7a/libflutter.so,omitempty"`
	ApktoolOutLibX8664LibappSo            []string `json:"apktool_out/lib/x86_64/libapp.so,omitempty"`
	ApktoolOutLibX8664LibencryptSo        []string `json:"apktool_out/lib/x86_64/libencrypt.so,omitempty"`
	ApktoolOutLibX8664LibnativeLibSo      []string `json:"apktool_out/lib/x86_64/libnative-lib.so,omitempty"`
	ApktoolOutLibX8664LibflutterSo        []string `json:"apktool_out/lib/x86_64/libflutter.so,omitempty"`
}

type Trackers struct {
	DetectedTrackers int           `json:"detected_trackers"`
	TotalTrackers    int           `json:"total_trackers"`
	Trackers         []interface{} `json:"trackers"`
}

type Url struct {
	Path string   `json:"path"`
	Urls []string `json:"urls"`
}
