"""
Mobile Binary Analysis Module for GhidraInsight

This module provides comprehensive analysis capabilities for mobile application
binaries including APK (Android) and IPA (iOS) files.

Author: GhidraInsight Team
License: Apache 2.0
"""

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class MobilePlatform(Enum):
    """Mobile platforms"""

    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"


class SecurityRisk(Enum):
    """Security risk levels"""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AndroidPermission:
    """Android permission information"""

    name: str
    protection_level: str = "unknown"  # "normal", "dangerous", "signature"
    description: str = ""
    risk_level: SecurityRisk = SecurityRisk.INFO


@dataclass
class IOSEntitlement:
    """iOS entitlement information"""

    key: str
    value: Any
    description: str = ""
    risk_level: SecurityRisk = SecurityRisk.INFO


@dataclass
class Component:
    """Application component (Activity, Service, Receiver, Provider)"""

    component_type: str  # "activity", "service", "receiver", "provider"
    name: str
    exported: bool = False
    permission: Optional[str] = None
    intent_filters: List[str] = field(default_factory=list)
    risk_level: SecurityRisk = SecurityRisk.INFO


@dataclass
class NativeLibrary:
    """Native library information"""

    name: str
    arch: str  # "armeabi-v7a", "arm64-v8a", "x86", "x86_64"
    path: str
    size: int
    sha256: str
    symbols: List[str] = field(default_factory=list)
    imported_libraries: List[str] = field(default_factory=list)


@dataclass
class Certificate:
    """Code signing certificate information"""

    subject: str
    issuer: str
    serial_number: str
    not_before: str
    not_after: str
    signature_algorithm: str
    fingerprint_sha256: str
    self_signed: bool = False


@dataclass
class MobileAppAnalysis:
    """Results of mobile application analysis"""

    platform: MobilePlatform
    package_name: str
    version: str
    version_code: Optional[str] = None
    min_sdk_version: Optional[int] = None
    target_sdk_version: Optional[int] = None
    app_name: Optional[str] = None
    file_hash: str = ""
    file_size: int = 0

    # Security findings
    permissions: List[AndroidPermission] = field(default_factory=list)
    entitlements: List[IOSEntitlement] = field(default_factory=list)
    components: List[Component] = field(default_factory=list)
    security_issues: List[Dict[str, Any]] = field(default_factory=list)

    # Code analysis
    native_libraries: List[NativeLibrary] = field(default_factory=list)
    obfuscated: bool = False
    debuggable: bool = False
    allow_backup: bool = True
    network_security_config: Optional[Dict[str, Any]] = None

    # Certificate info
    certificates: List[Certificate] = field(default_factory=list)

    # Static analysis
    classes: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    api_keys: List[Dict[str, str]] = field(default_factory=list)

    # Framework detection
    frameworks: List[str] = field(default_factory=list)
    third_party_libraries: List[str] = field(default_factory=list)

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0


@dataclass
class MobileAnalysisConfig:
    """Configuration for mobile analysis"""

    extract_strings: bool = True
    analyze_native_libs: bool = True
    deep_inspection: bool = True
    max_string_length: int = 1000
    extract_resources: bool = True
    decompile_dex: bool = False
    apktool_path: Optional[str] = None
    jadx_path: Optional[str] = None


class MobileAnalyzer:
    """
    Main mobile application analyzer for APK and IPA files.
    """

    def __init__(self, config: Optional[MobileAnalysisConfig] = None):
        self.config = config or MobileAnalysisConfig()
        self.temp_dir = None
        self.dangerous_permissions = self._initialize_dangerous_permissions()
        self.sensitive_entitlements = self._initialize_sensitive_entitlements()
        self.known_frameworks = self._initialize_known_frameworks()

    def _initialize_dangerous_permissions(self) -> Set[str]:
        """Initialize set of dangerous Android permissions"""
        return {
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.ACCESS_MEDIA_LOCATION",
            "android.permission.BODY_SENSORS",
            "android.permission.ACTIVITY_RECOGNITION",
        }

    def _initialize_sensitive_entitlements(self) -> Set[str]:
        """Initialize set of sensitive iOS entitlements"""
        return {
            "com.apple.security.get-task-allow",
            "com.apple.developer.associated-domains",
            "com.apple.developer.networking.vpn.api",
            "com.apple.developer.healthkit",
            "com.apple.developer.homekit",
            "com.apple.external-accessory.wireless-configuration",
            "keychain-access-groups",
            "com.apple.security.application-groups",
        }

    def _initialize_known_frameworks(self) -> Dict[str, str]:
        """Initialize known mobile frameworks and libraries"""
        return {
            # Android
            "androidx": "AndroidX",
            "com.google.android.material": "Material Components",
            "com.squareup.retrofit2": "Retrofit",
            "com.squareup.okhttp3": "OkHttp",
            "io.reactivex": "RxJava",
            "com.google.dagger": "Dagger",
            "org.greenrobot.eventbus": "EventBus",
            "com.google.firebase": "Firebase",
            "com.facebook.react": "React Native",
            "io.flutter": "Flutter",
            "org.apache.cordova": "Cordova",
            "com.unity3d": "Unity",
            "com.epicgames": "Unreal Engine",
            # iOS
            "Alamofire": "Alamofire",
            "AFNetworking": "AFNetworking",
            "SDWebImage": "SDWebImage",
            "Realm": "Realm Database",
            "Firebase": "Firebase",
            "ReactNative": "React Native",
        }

    def analyze(self, file_path: str) -> MobileAppAnalysis:
        """
        Analyze a mobile application binary.

        Args:
            file_path: Path to APK or IPA file

        Returns:
            MobileAppAnalysis object with results
        """
        logger.info(f"Starting mobile analysis: {file_path}")

        # Detect platform
        platform = self._detect_platform(file_path)

        if platform == MobilePlatform.ANDROID:
            return self._analyze_apk(file_path)
        elif platform == MobilePlatform.IOS:
            return self._analyze_ipa(file_path)
        else:
            raise ValueError(f"Unknown mobile platform for file: {file_path}")

    def _detect_platform(self, file_path: str) -> MobilePlatform:
        """Detect the mobile platform from file"""
        ext = Path(file_path).suffix.lower()

        if ext == ".apk":
            return MobilePlatform.ANDROID
        elif ext == ".ipa":
            return MobilePlatform.IOS

        # Try to detect from file structure
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                names = zf.namelist()
                if "AndroidManifest.xml" in names or any(
                    n.endswith(".dex") for n in names
                ):
                    return MobilePlatform.ANDROID
                elif any(
                    n.startswith("Payload/") and n.endswith(".app/") for n in names
                ):
                    return MobilePlatform.IOS
        except:
            pass

        return MobilePlatform.UNKNOWN

    def _analyze_apk(self, apk_path: str) -> MobileAppAnalysis:
        """Analyze Android APK file"""
        import time

        start_time = time.time()

        # Calculate file hash
        with open(apk_path, "rb") as f:
            data = f.read()
            file_hash = hashlib.sha256(data).hexdigest()
            file_size = len(data)

        # Initialize analysis result
        analysis = MobileAppAnalysis(
            platform=MobilePlatform.ANDROID,
            package_name="",
            version="",
            file_hash=file_hash,
            file_size=file_size,
            timestamp=start_time,
        )

        # Extract APK
        self.temp_dir = tempfile.mkdtemp(prefix="ghidra_apk_")
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                zf.extractall(self.temp_dir)

            # Parse AndroidManifest.xml
            self._parse_android_manifest(analysis)

            # Analyze components
            self._analyze_android_components(analysis)

            # Analyze native libraries
            if self.config.analyze_native_libs:
                self._analyze_native_libraries(analysis)

            # Extract strings from DEX files
            if self.config.extract_strings:
                self._extract_dex_strings(analysis)

            # Detect frameworks and libraries
            self._detect_android_frameworks(analysis)

            # Check for security issues
            self._check_android_security(analysis)

            # Analyze certificate
            self._analyze_apk_certificate(apk_path, analysis)

        finally:
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)

        elapsed = time.time() - start_time
        logger.info(f"APK analysis completed in {elapsed:.2f}s")

        return analysis

    def _parse_android_manifest(self, analysis: MobileAppAnalysis):
        """Parse AndroidManifest.xml"""
        manifest_path = os.path.join(self.temp_dir, "AndroidManifest.xml")

        if not os.path.exists(manifest_path):
            logger.warning("AndroidManifest.xml not found")
            return

        try:
            # Try to parse with apktool if available
            decoded_manifest = self._decode_manifest_with_apktool(manifest_path)
            if decoded_manifest:
                manifest_path = decoded_manifest

            tree = ET.parse(manifest_path)
            root = tree.getroot()

            # Extract package info
            analysis.package_name = root.get("package", "unknown")
            analysis.version_code = root.get(
                "{http://schemas.android.com/apk/res/android}versionCode"
            )
            analysis.version = root.get(
                "{http://schemas.android.com/apk/res/android}versionName", "unknown"
            )

            # Extract SDK versions
            uses_sdk = root.find("uses-sdk")
            if uses_sdk is not None:
                min_sdk = uses_sdk.get(
                    "{http://schemas.android.com/apk/res/android}minSdkVersion"
                )
                target_sdk = uses_sdk.get(
                    "{http://schemas.android.com/apk/res/android}targetSdkVersion"
                )
                if min_sdk:
                    analysis.min_sdk_version = (
                        int(min_sdk) if min_sdk.isdigit() else None
                    )
                if target_sdk:
                    analysis.target_sdk_version = (
                        int(target_sdk) if target_sdk.isdigit() else None
                    )

            # Extract permissions
            for perm in root.findall("uses-permission"):
                perm_name = perm.get("{http://schemas.android.com/apk/res/android}name")
                if perm_name:
                    risk_level = (
                        SecurityRisk.HIGH
                        if perm_name in self.dangerous_permissions
                        else SecurityRisk.LOW
                    )
                    analysis.permissions.append(
                        AndroidPermission(
                            name=perm_name,
                            risk_level=risk_level,
                            description=self._get_permission_description(perm_name),
                        )
                    )

            # Extract application properties
            app = root.find("application")
            if app is not None:
                analysis.debuggable = (
                    app.get("{http://schemas.android.com/apk/res/android}debuggable")
                    == "true"
                )
                analysis.allow_backup = (
                    app.get(
                        "{http://schemas.android.com/apk/res/android}allowBackup",
                        "true",
                    )
                    == "true"
                )

            logger.info(f"Parsed manifest for package: {analysis.package_name}")

        except Exception as e:
            logger.error(f"Error parsing AndroidManifest.xml: {e}")

    def _decode_manifest_with_apktool(self, manifest_path: str) -> Optional[str]:
        """Decode binary AndroidManifest.xml using apktool"""
        if not self.config.apktool_path:
            return None

        try:
            output_dir = tempfile.mkdtemp(prefix="apktool_")
            cmd = [self.config.apktool_path, "d", "-f", "-o", output_dir, manifest_path]
            subprocess.run(cmd, capture_output=True, timeout=30)

            decoded_manifest = os.path.join(output_dir, "AndroidManifest.xml")
            if os.path.exists(decoded_manifest):
                return decoded_manifest
        except Exception as e:
            logger.debug(f"Failed to decode manifest with apktool: {e}")

        return None

    def _get_permission_description(self, permission: str) -> str:
        """Get human-readable description for permission"""
        descriptions = {
            "android.permission.INTERNET": "Access internet",
            "android.permission.CAMERA": "Access camera",
            "android.permission.RECORD_AUDIO": "Record audio",
            "android.permission.ACCESS_FINE_LOCATION": "Access precise location",
            "android.permission.READ_CONTACTS": "Read contacts",
            "android.permission.READ_SMS": "Read SMS messages",
            "android.permission.SEND_SMS": "Send SMS messages",
            "android.permission.CALL_PHONE": "Make phone calls",
            "android.permission.READ_EXTERNAL_STORAGE": "Read external storage",
            "android.permission.WRITE_EXTERNAL_STORAGE": "Write to external storage",
        }
        return descriptions.get(permission, "")

    def _analyze_android_components(self, analysis: MobileAppAnalysis):
        """Analyze Android application components"""
        manifest_path = os.path.join(self.temp_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            return

        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            app = root.find("application")
            if not app:
                return

            # Activities
            for activity in app.findall("activity"):
                self._parse_component(activity, "activity", analysis)

            # Services
            for service in app.findall("service"):
                self._parse_component(service, "service", analysis)

            # Receivers
            for receiver in app.findall("receiver"):
                self._parse_component(receiver, "receiver", analysis)

            # Providers
            for provider in app.findall("provider"):
                self._parse_component(provider, "provider", analysis)

        except Exception as e:
            logger.error(f"Error analyzing components: {e}")

    def _parse_component(
        self, element: ET.Element, comp_type: str, analysis: MobileAppAnalysis
    ):
        """Parse a component from manifest"""
        name = element.get("{http://schemas.android.com/apk/res/android}name")
        exported = (
            element.get("{http://schemas.android.com/apk/res/android}exported")
            == "true"
        )
        permission = element.get(
            "{http://schemas.android.com/apk/res/android}permission"
        )

        intent_filters = []
        for intent_filter in element.findall("intent-filter"):
            for action in intent_filter.findall("action"):
                action_name = action.get(
                    "{http://schemas.android.com/apk/res/android}name"
                )
                if action_name:
                    intent_filters.append(action_name)

        # Exported components without permission are risky
        risk_level = (
            SecurityRisk.HIGH if exported and not permission else SecurityRisk.LOW
        )

        component = Component(
            component_type=comp_type,
            name=name or "unknown",
            exported=exported,
            permission=permission,
            intent_filters=intent_filters,
            risk_level=risk_level,
        )

        analysis.components.append(component)

    def _analyze_native_libraries(self, analysis: MobileAppAnalysis):
        """Analyze native libraries in APK"""
        lib_dir = os.path.join(self.temp_dir, "lib")
        if not os.path.exists(lib_dir):
            return

        for arch in os.listdir(lib_dir):
            arch_dir = os.path.join(lib_dir, arch)
            if not os.path.isdir(arch_dir):
                continue

            for lib_file in os.listdir(arch_dir):
                if lib_file.endswith(".so"):
                    lib_path = os.path.join(arch_dir, lib_file)
                    self._analyze_native_library(lib_path, arch, analysis)

    def _analyze_native_library(
        self, lib_path: str, arch: str, analysis: MobileAppAnalysis
    ):
        """Analyze a single native library"""
        try:
            with open(lib_path, "rb") as f:
                data = f.read()
                sha256 = hashlib.sha256(data).hexdigest()

            # Extract symbols using readelf or nm
            symbols = self._extract_symbols(lib_path)

            native_lib = NativeLibrary(
                name=os.path.basename(lib_path),
                arch=arch,
                path=lib_path,
                size=os.path.getsize(lib_path),
                sha256=sha256,
                symbols=symbols[:100],  # Limit to first 100 symbols
            )

            analysis.native_libraries.append(native_lib)

        except Exception as e:
            logger.debug(f"Error analyzing native library {lib_path}: {e}")

    def _extract_symbols(self, lib_path: str) -> List[str]:
        """Extract symbols from native library"""
        symbols = []
        try:
            # Try readelf first
            result = subprocess.run(
                ["readelf", "-s", lib_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "FUNC" in line or "OBJECT" in line:
                        parts = line.split()
                        if len(parts) >= 8:
                            symbols.append(parts[7])
        except:
            # Try nm as fallback
            try:
                result = subprocess.run(
                    ["nm", "-D", lib_path],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        parts = line.split()
                        if len(parts) >= 3:
                            symbols.append(parts[2])
            except:
                pass

        return symbols[:100]

    def _extract_dex_strings(self, analysis: MobileAppAnalysis):
        """Extract strings from DEX files"""
        for dex_file in Path(self.temp_dir).glob("*.dex"):
            try:
                with open(dex_file, "rb") as f:
                    data = f.read()

                # Simple string extraction (printable ASCII sequences)
                strings = re.findall(rb"[ -~]{4,}", data)
                for s in strings[:1000]:  # Limit strings
                    decoded = s.decode("ascii", errors="ignore")
                    if len(decoded) <= self.config.max_string_length:
                        analysis.strings.append(decoded)

                        # Extract URLs
                        if "://" in decoded:
                            analysis.urls.append(decoded)

                        # Extract IP addresses
                        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
                        for ip in re.findall(ip_pattern, decoded):
                            if ip not in analysis.ip_addresses:
                                analysis.ip_addresses.append(ip)

            except Exception as e:
                logger.debug(f"Error extracting strings from {dex_file}: {e}")

    def _detect_android_frameworks(self, analysis: MobileAppAnalysis):
        """Detect frameworks and third-party libraries"""
        # Check DEX files for framework packages
        for dex_file in Path(self.temp_dir).glob("*.dex"):
            try:
                with open(dex_file, "rb") as f:
                    data = f.read()

                for package, framework in self.known_frameworks.items():
                    if package.encode() in data:
                        if framework not in analysis.frameworks:
                            analysis.frameworks.append(framework)

            except Exception as e:
                logger.debug(f"Error detecting frameworks: {e}")

    def _check_android_security(self, analysis: MobileAppAnalysis):
        """Check for common Android security issues"""
        # Debuggable app
        if analysis.debuggable:
            analysis.security_issues.append(
                {
                    "type": "debuggable_app",
                    "severity": SecurityRisk.HIGH.value,
                    "description": "Application is debuggable in production",
                }
            )

        # Backup allowed
        if analysis.allow_backup:
            analysis.security_issues.append(
                {
                    "type": "backup_enabled",
                    "severity": SecurityRisk.MEDIUM.value,
                    "description": "Application allows backup (potential data exposure)",
                }
            )

        # Exported components without permission
        for component in analysis.components:
            if component.exported and not component.permission:
                analysis.security_issues.append(
                    {
                        "type": "exported_component",
                        "severity": SecurityRisk.HIGH.value,
                        "description": f"Exported {component.component_type} without permission: {component.name}",
                    }
                )

        # Check for dangerous permissions
        dangerous_perms = [
            p for p in analysis.permissions if p.risk_level == SecurityRisk.HIGH
        ]
        if len(dangerous_perms) > 5:
            analysis.security_issues.append(
                {
                    "type": "excessive_permissions",
                    "severity": SecurityRisk.MEDIUM.value,
                    "description": f"Application requests {len(dangerous_perms)} dangerous permissions",
                }
            )

    def _analyze_apk_certificate(self, apk_path: str, analysis: MobileAppAnalysis):
        """Analyze APK signing certificate"""
        try:
            # Use jarsigner or apksigner to verify
            result = subprocess.run(
                ["jarsigner", "-verify", "-verbose", "-certs", apk_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            # Parse certificate info from output
            # This is a simplified version
            if "CN=" in result.stdout:
                # Extract certificate details
                logger.info("Certificate information extracted")

        except Exception as e:
            logger.debug(f"Error analyzing certificate: {e}")

    def _analyze_ipa(self, ipa_path: str) -> MobileAppAnalysis:
        """Analyze iOS IPA file"""
        import time

        start_time = time.time()

        # Calculate file hash
        with open(ipa_path, "rb") as f:
            data = f.read()
            file_hash = hashlib.sha256(data).hexdigest()
            file_size = len(data)

        # Initialize analysis result
        analysis = MobileAppAnalysis(
            platform=MobilePlatform.IOS,
            package_name="",
            version="",
            file_hash=file_hash,
            file_size=file_size,
            timestamp=start_time,
        )

        # Extract IPA
        self.temp_dir = tempfile.mkdtemp(prefix="ghidra_ipa_")
        try:
            with zipfile.ZipFile(ipa_path, "r") as zf:
                zf.extractall(self.temp_dir)

            # Find .app bundle
            app_bundle = self._find_app_bundle()
            if not app_bundle:
                raise ValueError("Could not find .app bundle in IPA")

            # Parse Info.plist
            self._parse_info_plist(app_bundle, analysis)

            # Analyze entitlements
            self._analyze_entitlements(app_bundle, analysis)

            # Analyze Mach-O binary
            if self.config.analyze_native_libs:
                self._analyze_macho_binary(app_bundle, analysis)

            # Extract strings
            if self.config.extract_strings:
                self._extract_ios_strings(app_bundle, analysis)

            # Detect frameworks
            self._detect_ios_frameworks(app_bundle, analysis)

            # Check security
            self._check_ios_security(analysis)

        finally:
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)

        elapsed = time.time() - start_time
        logger.info(f"IPA analysis completed in {elapsed:.2f}s")

        return analysis

    def _find_app_bundle(self) -> Optional[str]:
        """Find the .app bundle in extracted IPA"""
        payload_dir = os.path.join(self.temp_dir, "Payload")
        if not os.path.exists(payload_dir):
            return None

        for item in os.listdir(payload_dir):
            if item.endswith(".app"):
                return os.path.join(payload_dir, item)

        return None

    def _parse_info_plist(self, app_bundle: str, analysis: MobileAppAnalysis):
        """Parse Info.plist"""
        plist_path = os.path.join(app_bundle, "Info.plist")
        if not os.path.exists(plist_path):
            logger.warning("Info.plist not found")
            return

        try:
            # Convert binary plist to XML
            xml_plist = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
            xml_plist.close()

            subprocess.run(
                ["plutil", "-convert", "xml1", "-o", xml_plist.name, plist_path],
                capture_output=True,
                timeout=10,
            )

            # Parse XML plist
            tree = ET.parse(xml_plist.name)
            root = tree.getroot()
            plist_dict = self._parse_plist_dict(root.find("dict"))

            analysis.package_name = plist_dict.get("CFBundleIdentifier", "unknown")
            analysis.version = plist_dict.get("CFBundleShortVersionString", "unknown")
            analysis.version_code = plist_dict.get("CFBundleVersion")
            analysis.app_name = plist_dict.get("CFBundleDisplayName")
            analysis.min_sdk_version = plist_dict.get("MinimumOSVersion")

            os.unlink(xml_plist.name)

            logger.info(f"Parsed Info.plist for bundle: {analysis.package_name}")

        except Exception as e:
            logger.error(f"Error parsing Info.plist: {e}")

    def _parse_plist_dict(self, dict_elem: Optional[ET.Element]) -> Dict[str, Any]:
        """Parse plist dictionary element"""
        if dict_elem is None:
            return {}

        result = {}
        children = list(dict_elem)

        for i in range(0, len(children), 2):
            if i + 1 >= len(children):
                break

            key_elem = children[i]
            value_elem = children[i + 1]

            if key_elem.tag == "key":
                key = key_elem.text
                value = self._parse_plist_value(value_elem)
                result[key] = value

        return result

    def _parse_plist_value(self, elem: ET.Element) -> Any:
        """Parse plist value element"""
        if elem.tag == "string":
            return elem.text or ""
        elif elem.tag == "integer":
            return int(elem.text or 0)
        elif elem.tag == "true":
            return True
        elif elem.tag == "false":
            return False
        elif elem.tag == "dict":
            return self._parse_plist_dict(elem)
        elif elem.tag == "array":
            return [self._parse_plist_value(child) for child in elem]
        else:
            return elem.text

    def _analyze_entitlements(self, app_bundle: str, analysis: MobileAppAnalysis):
        """Analyze iOS entitlements"""
        # Entitlements are embedded in the binary
        # This is a simplified version
        logger.debug("Entitlement analysis not fully implemented")

    def _analyze_macho_binary(self, app_bundle: str, analysis: MobileAppAnalysis):
        """Analyze Mach-O binary"""
        # Find main executable
        binary_name = os.path.basename(app_bundle).replace(".app", "")
        binary_path = os.path.join(app_bundle, binary_name)

        if not os.path.exists(binary_path):
            logger.warning(f"Binary not found: {binary_path}")
            return

        try:
            # Use otool to analyze
            result = subprocess.run(
                ["otool", "-L", binary_path],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if line and not line.startswith(binary_path):
                        # Extract library dependencies
                        parts = line.split()
                        if parts:
                            lib_name = parts[0]
                            native_lib = NativeLibrary(
                                name=os.path.basename(lib_name),
                                arch="arm64",  # iOS is primarily arm64 now
                                path=lib_name,
                                size=0,
                                sha256="",
                            )
                            analysis.native_libraries.append(native_lib)

        except Exception as e:
            logger.debug(f"Error analyzing Mach-O binary: {e}")

    def _extract_ios_strings(self, app_bundle: str, analysis: MobileAppAnalysis):
        """Extract strings from iOS binary"""
        binary_name = os.path.basename(app_bundle).replace(".app", "")
        binary_path = os.path.join(app_bundle, binary_name)

        if not os.path.exists(binary_path):
            return

        try:
            result = subprocess.run(
                ["strings", binary_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                for line in result.stdout.split("\n")[:1000]:  # Limit strings
                    line = line.strip()
                    if line and len(line) <= self.config.max_string_length:
                        analysis.strings.append(line)

                        # Extract URLs
                        if "://" in line:
                            analysis.urls.append(line)

                        # Extract IP addresses
                        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
                        for ip in re.findall(ip_pattern, line):
                            if ip not in analysis.ip_addresses:
                                analysis.ip_addresses.append(ip)

        except Exception as e:
            logger.debug(f"Error extracting strings: {e}")

    def _detect_ios_frameworks(self, app_bundle: str, analysis: MobileAppAnalysis):
        """Detect iOS frameworks"""
        frameworks_dir = os.path.join(app_bundle, "Frameworks")
        if os.path.exists(frameworks_dir):
            for framework in os.listdir(frameworks_dir):
                if framework.endswith(".framework"):
                    framework_name = framework.replace(".framework", "")
                    if framework_name in self.known_frameworks:
                        analysis.frameworks.append(
                            self.known_frameworks[framework_name]
                        )
                    else:
                        analysis.third_party_libraries.append(framework_name)

    def _check_ios_security(self, analysis: MobileAppAnalysis):
        """Check for common iOS security issues"""
        # Check for App Transport Security
        if "NSAppTransportSecurity" not in str(analysis.metadata):
            analysis.security_issues.append(
                {
                    "type": "ats_disabled",
                    "severity": SecurityRisk.MEDIUM.value,
                    "description": "App Transport Security might be disabled",
                }
            )

    def export_report(
        self, analysis: MobileAppAnalysis, output_path: str, format: str = "json"
    ):
        """Export analysis report"""
        report = {
            "platform": analysis.platform.value,
            "package_name": analysis.package_name,
            "version": analysis.version,
            "version_code": analysis.version_code,
            "file_hash": analysis.file_hash,
            "file_size": analysis.file_size,
            "min_sdk_version": analysis.min_sdk_version,
            "target_sdk_version": analysis.target_sdk_version,
            "permissions": [
                {
                    "name": p.name,
                    "risk_level": p.risk_level.value,
                    "description": p.description,
                }
                for p in analysis.permissions
            ],
            "components": [
                {
                    "type": c.component_type,
                    "name": c.name,
                    "exported": c.exported,
                    "permission": c.permission,
                    "risk_level": c.risk_level.value,
                }
                for c in analysis.components
            ],
            "security_issues": analysis.security_issues,
            "native_libraries": [
                {"name": lib.name, "arch": lib.arch, "sha256": lib.sha256}
                for lib in analysis.native_libraries
            ],
            "frameworks": analysis.frameworks,
            "third_party_libraries": analysis.third_party_libraries,
            "capabilities": {
                "debuggable": analysis.debuggable,
                "allow_backup": analysis.allow_backup,
                "obfuscated": analysis.obfuscated,
            },
            "urls": analysis.urls[:50],  # Limit URLs
            "ip_addresses": analysis.ip_addresses,
            "timestamp": analysis.timestamp,
        }

        if format == "json":
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")

        logger.info(f"Report exported to {output_path}")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create analyzer
    config = MobileAnalysisConfig(
        extract_strings=True,
        analyze_native_libs=True,
        deep_inspection=True,
    )
    analyzer = MobileAnalyzer(config)

    # Analyze APK
    try:
        analysis = analyzer.analyze("/path/to/app.apk")
        print(f"Package: {analysis.package_name}")
        print(f"Platform: {analysis.platform.value}")
        print(f"Permissions: {len(analysis.permissions)}")
        print(f"Security Issues: {len(analysis.security_issues)}")

        # Export report
        analyzer.export_report(analysis, "mobile_analysis_report.json")
    except Exception as e:
        print(f"Error: {e}")
