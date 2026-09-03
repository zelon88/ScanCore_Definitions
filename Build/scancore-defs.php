<?php
// / -----------------------------------------------------------------------------------
// / COPYRIGHT INFORMATION ...
// / ScanCore_Definitions, Copyright on 9/3/2026 by Justin Grimes, www.github.com/zelon88
// / 
// / LICENSE INFORMATION ...
// / This project is protected by the GNU GPLv3 Open-Source license.
// / BSD or MIT licensing is available. Reach out to @zelon88 for more information.
// / https://www.gnu.org/licenses/gpl-3.0.html
// / 
// / APPLICATION INFORMATION ...
// / This application collects raw threat feeds & builds them into ScanCore definitions.
// / It is standalone. Nothing here reads or writes any part of a ScanCore installation.
// / ScanCore downloads the files this application builds. It never runs this application.
// / 
// / FILE INFORMATION ...
// / v1.8.
// / This file contains the core logic of the ScanCore_Definitions application.
// / 
// / DEPENDENCY REQUIREMENTS ...
// / This application should run on Linux or Windows systems with PHP 8.0 (or later).
// / A recipe with no url needs no network access at all.
// / 
// / COMPONENT REQUIREMENTS ...
// / This file refuses to operate without both of the following, at the versions named:
// /   scancore-defs-version.php   EXACT match. It & this file are one release.
// /   scancore-defs-config.php    MINIMUM match. A newer configuration carrying every
// /                               required setting is fine. An older one may not carry
// /                               a setting this builder now depends upon.
// / A half applied update otherwise leaves a builder reading a configuration that does
// / not hold what it expects, which produces a definition file that looks correct & is
// / not. Refusing to start is cheaper than shipping that.
// / 
// / HOW THIS WORKS ...
// / A recipe describes one source. Where to fetch it, how to read it & what it may
// / become. The raw download is kept in Sources exactly as it arrived, so a build is
// / always reproducible from committed data & a bad feed stays traceable.
// / 
// / A source that a recipe marks as redistributable is built into the definition files
// / this repository publishes. A source that is not is built into Local, which is never
// / committed. That split exists because a data feed & this repository do not share a
// / license, & shipping someone elses data under GPLv3 would hand a downstream operator
// / an obligation they never agreed to.
// / 
// / VALID SWITCHES / ARGUMENTS / USAGE ...
// / 
// /   php Build/scancore-defs.php --all
// / 
// /   Fetch every enabled recipe:             --fetch
// /   Build definition files from Sources:    --build
// /   Verify the built definition files:      --verify
// /   Do all three in order:                  --all
// /   Only handle publishable sources:        --redistributable-only
// /   Work on one recipe only:                --recipe <name>
// /   Never touch the network:                --offline
// /   Explain what would happen, change none: --dry-run
// /   Report only what matters:               --quiet
// / 
// / EXIT STATUS ...
// / A status of 0 is returned when the requested operation completed.
// / A status of 1 is returned when a component check, a recipe or a verify step failed.
// / 
// / NAMING CONVENTIONS ...
// / Upper case first letter variables are global in scope.
// / Lower case first letter variables never leave the function that initialized them.
// / The only documented exception is $argv, which PHP itself defines for us.
// / 
// / <3 Open-Source
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / The version of this file. The version manifest must match it exactly & the
// / configuration file must be equal to it or newer. Both are checked before any work
// / begins, in the main logic at the bottom of this file.
$DefsCoreVersion = 'v1.8';
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to release values from memory as soon as they stop being needed.
function purgeSensitiveMemory(&...$variables) {
  // / Set variables.
  $MemoryPurged = FALSE;
  foreach ($variables as $purgeKey => $purgeValue) {
    $variables[$purgeKey] = NULL;
    $MemoryPurged = TRUE; }
  return $MemoryPurged; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to reset a narrow scope variable to a known value inside a loop body.
function redeclare(&$variable, $value = NULL) {
  $variable = NULL;
  $variable = $value; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to compare two version numbers numerically rather than as strings.
// / A string comparison ranks 24.2 below 7.6 & ranks 3.10 below 3.9, so we never use one.
// / A leading v is stripped first, because casting 'v3' to an integer yields 0.
function compareDefsVersions($requiredVersion, $suppliedVersion) {
  // / Set variables.
  $VersionsCompared = $SuppliedIsAcceptable = $SuppliedIsIdentical = FALSE;
  $requiredParts = $suppliedParts = array();
  $requiredClean = ltrim(strtolower(trim(strval($requiredVersion))), 'v');
  $suppliedClean = ltrim(strtolower(trim(strval($suppliedVersion))), 'v');
  $partIndex = $partTop = 0;
  // / A build that reports no parseable version cannot be cleared, so it is refused.
  if (preg_match('/^[0-9]+(\.[0-9]+)*$/', $requiredClean) && preg_match('/^[0-9]+(\.[0-9]+)*$/', $suppliedClean)) {
    $VersionsCompared = TRUE;
    $requiredParts = explode('.', $requiredClean);
    $suppliedParts = explode('.', $suppliedClean);
    while (count($requiredParts) < count($suppliedParts)) $requiredParts[] = '0';
    while (count($suppliedParts) < count($requiredParts)) $suppliedParts[] = '0';
    $SuppliedIsAcceptable = $SuppliedIsIdentical = TRUE;
    $partTop = count($requiredParts);
    while ($partIndex < $partTop) {
      if (intval($suppliedParts[$partIndex]) > intval($requiredParts[$partIndex])) {
        $SuppliedIsIdentical = FALSE;
        $partIndex = $partTop; }
      else {
        if (intval($suppliedParts[$partIndex]) < intval($requiredParts[$partIndex])) {
          $SuppliedIsAcceptable = $SuppliedIsIdentical = FALSE;
          $partIndex = $partTop; }
        else $partIndex++; } } }
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($requiredParts, $suppliedParts, $requiredClean, $suppliedClean, $partIndex, $partTop);
  return array($VersionsCompared, $SuppliedIsAcceptable, $SuppliedIsIdentical); }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to load the version manifest & the configuration, & to check both.
// / Nothing else runs until this passes. A builder reading a configuration from a
// / different release produces a definition file that looks correct & is not.
function loadDefsComponents($coreVersion) {
  global $DefsVersion, $DefsFormatVersion, $DefsProjectName, $DefsRepositoryURL;
  global $DefsConfigVersion, $DefsRepoRoot, $DefsSourceDirName, $DefsLocalDirName;
  global $DefsRecipeDirName, $DefsPolicyDirName, $DefsLimitsFileName, $DefsAllowlistFileName;
  global $DefsBuildReportFileName, $DefsOutputPrefix, $DefsStagingSuffix;
  global $DefsFetchTimeout, $DefsUserAgent, $DefsFollowRedirects, $EOL;
  // / Set variables.
  $ComponentsLoaded = FALSE;
  $ComponentFault = '';
  $componentDir = realpath(dirname(__FILE__));
  $versionFile = $componentDir.DIRECTORY_SEPARATOR.'scancore-defs-version.php';
  $configFile = $componentDir.DIRECTORY_SEPARATOR.'scancore-defs-config.php';
  $versionsCompared = $versionAcceptable = $versionIdentical = FALSE;
  if (!file_exists($versionFile)) $ComponentFault = 'the version manifest is missing:  '.$versionFile;
  else {
    if (!file_exists($configFile)) $ComponentFault = 'the configuration file is missing:  '.$configFile;
    else {
      require_once ($versionFile);
      require_once ($configFile);
      if (!isset($DefsVersion)) $ComponentFault = 'the version manifest declares no $DefsVersion';
      else {
        if (!isset($DefsConfigVersion)) $ComponentFault = 'the configuration file declares no $DefsConfigVersion';
        else {
          // / The manifest & this file are one release, so they must agree exactly.
          list($versionsCompared, $versionAcceptable, $versionIdentical) = compareDefsVersions($coreVersion, $DefsVersion);
          if (!$versionsCompared) $ComponentFault = 'the version manifest reports no parseable version:  '.$DefsVersion;
          else {
            if (!$versionIdentical) $ComponentFault = 'the version manifest is '.$DefsVersion.' & this builder is '.$coreVersion.'. They are released together & must match exactly';
            else {
              // / The configuration is a minimum match, so a newer one is welcome.
              list($versionsCompared, $versionAcceptable, $versionIdentical) = compareDefsVersions($coreVersion, $DefsConfigVersion);
              if (!$versionsCompared) $ComponentFault = 'the configuration file reports no parseable version:  '.$DefsConfigVersion;
              else {
                if (!$versionAcceptable) $ComponentFault = 'the configuration file is '.$DefsConfigVersion.' & this builder is '.$coreVersion.'. A configuration older than the builder may not carry a setting the builder now depends upon';
                else $ComponentsLoaded = TRUE; } } } } } } }
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($componentDir, $versionFile, $configFile, $versionsCompared, $versionAcceptable, $versionIdentical, $coreVersion);
  return array($ComponentsLoaded, $ComponentFault); }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to report progress & to collect anything the report should mention.
function buildOutput($text, $level, $alwaysShow) {
  global $ReportLines, $Quiet, $EOL;
  // / Set variables.
  $OutputWritten = FALSE;
  $preText = '';
  if ($level === 'warning') $preText = 'WARNING!!!  ';
  if ($level === 'error') $preText = 'ERROR!!!    ';
  if ($level === 'drop') $preText = 'DROPPED     ';
  // / Everything except plain progress belongs in the report the build leaves behind.
  if ($level !== 'log') $ReportLines[] = $preText.$text;
  if ($alwaysShow or !$Quiet) {
    echo $preText.$text.$EOL;
    $OutputWritten = TRUE; }
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($preText, $text, $level);
  return $OutputWritten; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to read a key & value file into an array.
// / Used for a recipe & for the limits policy, which share the same simple shape.
function readSettingsFile($settingsFile) {
  // / Set variables.
  $Settings = array();
  $rawLines = array();
  $equalsPosition = 0;
  $settingKey = $settingValue = '';
  if (file_exists($settingsFile)) {
    $rawLines = file($settingsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($rawLines)) $rawLines = array();
    foreach ($rawLines as $rawLine) {
      if (substr(trim($rawLine), 0, 1) !== '#' && trim($rawLine) !== '') {
        redeclare($equalsPosition, strpos($rawLine, '='));
        if ($equalsPosition !== FALSE) {
          redeclare($settingKey, strtolower(trim(substr($rawLine, 0, $equalsPosition))));
          redeclare($settingValue, trim(substr($rawLine, $equalsPosition + 1)));
          if ($settingKey !== '') $Settings[$settingKey] = $settingValue; } } } }
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($rawLines, $rawLine, $equalsPosition, $settingKey, $settingValue, $settingsFile);
  return $Settings; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to read the allowlist of values that may never become an indicator.
function readAllowlist($allowlistFile) {
  // / Set variables.
  $Allowlist = array();
  $rawLines = array();
  if (file_exists($allowlistFile)) {
    $rawLines = file($allowlistFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($rawLines)) $rawLines = array();
    foreach ($rawLines as $rawLine) if (substr(trim($rawLine), 0, 1) !== '#' && trim($rawLine) !== '') $Allowlist[] = strtolower(trim($rawLine)); }
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($rawLines, $rawLine, $allowlistFile);
  return $Allowlist; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to resolve a recipe field that may name a literal or a column.
// / A recipe writes  value = column 3  or  label = Malware.URLhaus  & both are common.
function resolveRecipeField($fieldText, $rowFields) {
  // / Set variables.
  $ResolvedValue = '';
  $columnNumber = 0;
  if (substr(strtolower(trim($fieldText)), 0, 7) === 'column ') {
    $columnNumber = intval(trim(substr(trim($fieldText), 7)));
    // / A recipe counts columns from one, the way a person reading the file would.
    if ($columnNumber > 0 && isset($rowFields[$columnNumber - 1])) $ResolvedValue = trim($rowFields[$columnNumber - 1]); }
  else $ResolvedValue = trim($fieldText);
  // / Strip the quoting that a comma separated export puts around every field.
  $ResolvedValue = trim($ResolvedValue, '"');
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($columnNumber, $fieldText, $rowFields);
  return $ResolvedValue; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to reduce a url or a host to the bare host name it contains.
// / The allowlist is compared against a host, so a url has to be reduced before it can
// / be checked. Otherwise a malicious path on an allowlisted host would slip through
// / while a mention of that host in prose would not.
function hostNameOf($indicatorValue) {
  // / Set variables.
  $HostName = strtolower(trim($indicatorValue));
  $HostName = preg_replace('#^[a-z][a-z0-9+.\-]*://#', '', $HostName);
  $HostName = explode('/', $HostName)[0];
  $HostName = explode('?', $HostName)[0];
  $HostName = explode('@', $HostName);
  $HostName = $HostName[count($HostName) - 1];
  $HostName = explode(':', $HostName)[0];
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($indicatorValue);
  return $HostName; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to measure how much variety a value carries, in bits per byte.
// / A byte signature is matched against every byte of every file scanned, so a value
// / made of one repeated byte matches the padding in ordinary binaries constantly.
// / A real certificate serial measures around 3.5. A run of zero bytes measures 0.5.
function valueEntropy($value) {
  // / Set variables.
  $ValueEntropy = 0.0;
  $byteCounts = array();
  $valueLength = strlen($value);
  $byteIndex = 0;
  $byteFrequency = 0.0;
  if ($valueLength > 0) {
    while ($byteIndex < $valueLength) {
      $byteCounts[$value[$byteIndex]] = isset($byteCounts[$value[$byteIndex]]) ? $byteCounts[$value[$byteIndex]] + 1 : 1;
      $byteIndex++; }
    foreach ($byteCounts as $byteCount) {
      $byteFrequency = $byteCount / $valueLength;
      $ValueEntropy = $ValueEntropy - ($byteFrequency * log($byteFrequency, 2)); } }
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($byteCounts, $valueLength, $byteIndex, $byteFrequency, $byteCount, $value);
  return $ValueEntropy; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to measure the longest run of one repeated byte inside a value.
function longestByteRun($value) {
  // / Set variables.
  $LongestByteRun = 0;
  $currentRun = 0;
  $byteIndex = 0;
  if (strlen($value) > 0) {
    $LongestByteRun = $currentRun = 1;
    $byteIndex = 1;
    while ($byteIndex < strlen($value)) {
      if ($value[$byteIndex] === $value[$byteIndex - 1]) $currentRun++;
      else $currentRun = 1;
      if ($currentRun > $LongestByteRun) $LongestByteRun = $currentRun;
      $byteIndex++; } }
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($currentRun, $byteIndex, $value);
  return $LongestByteRun; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to decide whether an indicator is allowed to become a definition.
// / Every refusal is reported, because a silent refusal is how a feed quietly stops
// / contributing anything & nobody notices for a year.
function indicatorIsAcceptable($indicatorKind, $indicatorValue, $recipeName) {
  global $Limits, $Allowlist, $DropCounts;
  // / Set variables.
  $IndicatorIsAcceptable = TRUE;
  $refusalReason = '';
  $hostName = '';
  $expectedLength = 0;
  $minimumLength = $maximumLength = $maximumRun = 0;
  $minimumEntropy = 0.0;
  // / A hash has one correct length & anything else is a broken record, not a short one.
  if ($indicatorKind === 'md5') $expectedLength = 32;
  if ($indicatorKind === 'sha1') $expectedLength = 40;
  if ($indicatorKind === 'sha256') $expectedLength = 64;
  if ($expectedLength > 0) {
    if (!preg_match('/^[0-9a-f]{'.$expectedLength.'}$/', $indicatorValue)) {
      $IndicatorIsAcceptable = FALSE;
      $refusalReason = 'not a whole '.$indicatorKind; } }
  else {
    // / A string indicator is measured against the length policy for its kind.
    $minimumLength = isset($Limits['minlength '.$indicatorKind]) ? intval($Limits['minlength '.$indicatorKind]) : 1;
    $maximumLength = isset($Limits['maxlength '.$indicatorKind]) ? intval($Limits['maxlength '.$indicatorKind]) : 4096;
    if (strlen($indicatorValue) < $minimumLength) {
      $IndicatorIsAcceptable = FALSE;
      $refusalReason = 'shorter than the '.$minimumLength.' character minimum for '.$indicatorKind; }
    if ($IndicatorIsAcceptable && strlen($indicatorValue) > $maximumLength) {
      $IndicatorIsAcceptable = FALSE;
      $refusalReason = 'longer than the '.$maximumLength.' character maximum for '.$indicatorKind; }
    // / A content signature has to carry enough variety to mean something on its own.
    // / A certificate serial of eight zero bytes is a valid serial & a useless signature,
    // / because it matches the padding in almost every binary file that exists.
    if ($IndicatorIsAcceptable && $indicatorKind === 'data') {
      $minimumEntropy = isset($Limits['minentropy data']) ? floatval($Limits['minentropy data']) : 0;
      $maximumRun = isset($Limits['maxrun data']) ? intval($Limits['maxrun data']) : 4096;
      if (valueEntropy($indicatorValue) < $minimumEntropy) {
        $IndicatorIsAcceptable = FALSE;
        $refusalReason = 'too little variety to be a signature, '.number_format(valueEntropy($indicatorValue), 2).' bits per byte against a minimum of '.$minimumEntropy; }
      if ($IndicatorIsAcceptable && longestByteRun($indicatorValue) > $maximumRun) {
        $IndicatorIsAcceptable = FALSE;
        $refusalReason = 'holds a run of '.longestByteRun($indicatorValue).' identical bytes against a maximum of '.$maximumRun; } }
    // / A host or url is checked against the allowlist, reduced to its host name first.
    if ($IndicatorIsAcceptable && ($indicatorKind === 'host' or $indicatorKind === 'url')) {
      redeclare($hostName, hostNameOf($indicatorValue));
      foreach ($Allowlist as $allowedHost) if ($IndicatorIsAcceptable) {
        // / An allowlist entry covers the host itself & everything underneath it.
        if ($hostName === $allowedHost or substr($hostName, 0 - (strlen($allowedHost) + 1)) === '.'.$allowedHost) {
          $IndicatorIsAcceptable = FALSE;
          $refusalReason = 'the host is on the allowlist'; } } }
    // / A name or data indicator is checked against the allowlist as a whole string.
    if ($IndicatorIsAcceptable) foreach ($Allowlist as $allowedHost) if ($IndicatorIsAcceptable) {
      if (strtolower($indicatorValue) === $allowedHost) {
        $IndicatorIsAcceptable = FALSE;
        $refusalReason = 'the value is on the allowlist'; } } }
  if (!$IndicatorIsAcceptable) {
    if (!isset($DropCounts[$recipeName.'|'.$refusalReason])) $DropCounts[$recipeName.'|'.$refusalReason] = 0;
    $DropCounts[$recipeName.'|'.$refusalReason]++; }
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($refusalReason, $hostName, $expectedLength, $minimumLength, $maximumLength, $minimumEntropy, $maximumRun, $allowedHost);
  return $IndicatorIsAcceptable; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to render one definition line in the ScanCore definition format.
// / The value is quoted whenever it is not a hash, because a string indicator may carry
// / leading or trailing whitespace that matters & a hash never can.
function formatDefinitionLine($indicatorKind, $indicatorName, $indicatorValue, $attributes) {
  // / Set variables.
  $DefinitionLine = '';
  $renderedValue = $indicatorValue;
  $attributeText = '';
  if ($indicatorKind !== 'md5' && $indicatorKind !== 'sha1' && $indicatorKind !== 'sha256') {
    // / A definition file has to stay a text file a person can read in a diff, so any
    // / byte without a printable form is written as the escape that names it.
    // / The backslash & the double quote are escaped too, even though both are printable.
    // / Leaving a raw backslash in would make the value ambiguous, because a signature
    // / holding the four bytes of the text \\x1c would decode back as the one byte 0x1c.
    $renderedValue = preg_replace_callback('/[^\x20-\x21\x23-\x5B\x5D-\x7E]/', function($byteMatch) { return sprintf('\\x%02x', ord($byteMatch[0])); }, $indicatorValue);
    $renderedValue = '"'.$renderedValue.'"'; }
  foreach ($attributes as $attributeKey => $attributeValue) if ($attributeValue !== '') $attributeText = $attributeText.' '.$attributeKey.'='.$attributeValue;
  $DefinitionLine = sprintf('%-6s %-44s = %s%s', $indicatorKind, $indicatorName, $renderedValue, $attributeText);
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($renderedValue, $attributeText, $attributeKey, $attributeValue, $attributes);
  return $DefinitionLine; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to say where a recipe keeps its raw downloaded source.
// / A source that may not be redistributed lives under Sources/Local, which is ignored
// / by git. Committing the raw download of a feed we are not allowed to republish would
// / redistribute it just as surely as committing the built definitions would.
function recipeSourcePath($recipe) {
  global $RepoRoot, $SEP, $DefsSourceDirName, $DefsLocalDirName;
  // / Set variables.
  $SourcePath = $RepoRoot.$SEP.$DefsSourceDirName.$SEP.basename($recipe['file']);
  if (strtolower(trim($recipe['redistribute'])) !== 'yes') {
    if (!is_dir($RepoRoot.$SEP.$DefsSourceDirName.$SEP.$DefsLocalDirName)) @mkdir($RepoRoot.$SEP.$DefsSourceDirName.$SEP.$DefsLocalDirName, 0755, TRUE);
    $SourcePath = $RepoRoot.$SEP.$DefsSourceDirName.$SEP.$DefsLocalDirName.$SEP.basename($recipe['file']); }
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($recipe);
  return $SourcePath; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to download one recipe source into the Sources directory.
// / The download is written exactly as it arrived. Nothing is reformatted here, so a
// / build is always reproducible from what is committed & a bad feed stays traceable.
function fetchRecipeSource($recipeName, $recipe) {
  global $RepoRoot, $SEP, $DryRun, $DefsStagingSuffix, $DefsFetchTimeout, $DefsUserAgent, $DefsFollowRedirects;
  // / Set variables.
  $SourceFetched = FALSE;
  $sourceFile = recipeSourcePath($recipe);
  $stagedFile = $sourceFile.$DefsStagingSuffix;
  $streamContext = NULL;
  $headerText = '';
  $fetchedData = FALSE;
  $authValue = $fetchUrl = $safeUrl = '';
  // / A recipe with no url describes a file that is maintained by hand.
  if (!isset($recipe['url']) or trim($recipe['url']) === '') {
    buildOutput('Recipe '.$recipeName.' has no url, so its source file is used as it stands.', 'log', FALSE);
    $SourceFetched = file_exists($sourceFile); }
  else {
    // / Supply the authentication key when the recipe names an environment variable.
    // / A key may belong in a header or in the address itself, & providers use both.
    $fetchUrl = trim($recipe['url']);
    if (isset($recipe['authenv']) && trim($recipe['authenv']) !== '') {
      $authValue = strval(getenv(trim($recipe['authenv'])));
      if ($authValue === '') buildOutput('Recipe '.$recipeName.' needs '.$recipe['authenv'].' in the environment & it is not set.', 'warning', TRUE);
      else {
        if (isset($recipe['authheader']) && trim($recipe['authheader']) !== '') $headerText = trim($recipe['authheader']).': '.$authValue."\r\n";
        if (strpos($fetchUrl, '{AUTHKEY}') !== FALSE) $fetchUrl = str_replace('{AUTHKEY}', rawurlencode($authValue), $fetchUrl); } }
    // / Never print a key. An address carrying one is reported with the key masked out.
    $safeUrl = str_replace('{AUTHKEY}', '{AUTHKEY}', trim($recipe['url']));
    if ($DryRun) {
      buildOutput('Would fetch '.$recipeName.' from '.$safeUrl, 'log', TRUE);
      $SourceFetched = file_exists($sourceFile); }
    else {
      $streamContext = stream_context_create(array('http' => array('timeout' => intval($DefsFetchTimeout), 'follow_location' => ($DefsFollowRedirects ? 1 : 0), 'user_agent' => $DefsUserAgent, 'header' => $headerText)));
      $fetchedData = @file_get_contents($fetchUrl, FALSE, $streamContext);
      if (!is_string($fetchedData) or trim($fetchedData) === '') buildOutput('Cannot fetch '.$recipeName.' from '.$safeUrl, 'error', TRUE);
      else {
        // / Stage the download & only replace the committed source once it has arrived whole.
        if (@file_put_contents($stagedFile, $fetchedData) === FALSE) buildOutput('Cannot stage the download for '.$recipeName, 'error', TRUE);
        else {
          if (file_exists($sourceFile)) @unlink($sourceFile);
          $SourceFetched = @rename($stagedFile, $sourceFile);
          if ($SourceFetched) buildOutput('Fetched '.$recipeName.', '.strlen($fetchedData).' bytes.', 'log', FALSE); } } } }
  if (file_exists($stagedFile)) @unlink($stagedFile);
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($sourceFile, $stagedFile, $streamContext, $headerText, $fetchedData, $authValue, $fetchUrl, $safeUrl, $recipe);
  return $SourceFetched; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to turn one recipe & its raw source into a list of definition records.
function buildRecipeIndicators($recipeName, $recipe) {
  global $RepoRoot, $SEP, $BuildDate, $RecipeYieldFailure, $DefsProjectName, $DropCounts, $Limits;
  // / Set variables.
  $Indicators = array();
  $sourceFile = recipeSourcePath($recipe);
  $rawLines = array();
  $skipRemaining = 0;
  $delimiter = ',';
  $commentMarker = '#';
  $rowFields = array();
  $indicatorKind = $indicatorName = $indicatorValue = '';
  $acceptedCount = $shortestAccepted = $longestAcceptedRun = 0;
  $lowestEntropy = -1.0;
  $acceptedEntropy = 0.0;
  $marginText = '';
  $nullValues = array();
  if (isset($recipe['nullvalues'])) foreach (explode(',', $recipe['nullvalues']) as $nullEntry) if (trim($nullEntry) !== '') $nullValues[] = strtolower(trim($nullEntry));
  if (!file_exists($sourceFile)) buildOutput('Recipe '.$recipeName.' has no source file at '.$sourceFile, 'error', TRUE);
  else {
    if (isset($recipe['comment'])) $commentMarker = trim($recipe['comment']);
    if (strtolower(trim($recipe['format'])) === 'tsv') $delimiter = "\t";
    if (isset($recipe['delimiter']) && trim($recipe['delimiter']) !== '') $delimiter = trim($recipe['delimiter']);
    $skipRemaining = isset($recipe['skiplines']) ? intval($recipe['skiplines']) : 0;
    $rawLines = file($sourceFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($rawLines)) $rawLines = array();
    foreach ($rawLines as $rawLine) {
      if ($skipRemaining > 0) $skipRemaining--;
      else {
        if (trim($rawLine) !== '' && ($commentMarker === '' or substr(trim($rawLine), 0, strlen($commentMarker)) !== $commentMarker)) {
          // / A comma separated export quotes its fields, so it is parsed rather than split.
          if (strtolower(trim($recipe['format'])) === 'csv') redeclare($rowFields, str_getcsv($rawLine, $delimiter, '"', '\\'));
          else {
            if (strtolower(trim($recipe['format'])) === 'lines') redeclare($rowFields, array($rawLine));
            else redeclare($rowFields, explode($delimiter, $rawLine)); }
          redeclare($indicatorKind, strtolower(resolveRecipeField($recipe['kind'], $rowFields)));
          redeclare($indicatorName, resolveRecipeField($recipe['label'], $rowFields));
          if (isset($recipe['labelprefix'])) {
            if (in_array(strtolower($indicatorName), $nullValues, TRUE)) redeclare($indicatorName, trim(isset($recipe['labeldefault']) ? $recipe['labeldefault'] : ''));
            redeclare($indicatorName, trim($recipe['labelprefix']).preg_replace('/[^A-Za-z0-9._-]+/', '', $indicatorName)); }
          redeclare($indicatorValue, resolveRecipeField($recipe['value'], $rowFields));
          // / A feed writes a placeholder where it has no value. MalwareBazaar writes
          // / None for an absent sha1 & n/a for an unattributed sample. Those are the
          // / absence of data & must not be built into a definition that names them.
          if (in_array(strtolower($indicatorValue), $nullValues, TRUE)) redeclare($indicatorValue, '');
          if (in_array(strtolower($indicatorName), $nullValues, TRUE)) redeclare($indicatorName, trim(isset($recipe['labeldefault']) ? $recipe['labeldefault'] : ''));
          // / A hex column names bytes rather than text, so decode it before it is measured.
          // / A certificate serial number is stored in a signed file as bytes, never as hex.
          if (isset($recipe['transform']) && strtolower(trim($recipe['transform'])) === 'hexbytes') {
            if (preg_match('/^[0-9a-fA-F]+$/', $indicatorValue) && strlen($indicatorValue) % 2 === 0) redeclare($indicatorValue, hex2bin($indicatorValue));
            else redeclare($indicatorValue, ''); }
          // / A hash is stored lower case so an exact comparison never depends on casing.
          if ($indicatorKind === 'md5' or $indicatorKind === 'sha1' or $indicatorKind === 'sha256') $indicatorValue = strtolower($indicatorValue);
          // / A row that maps to nothing usable is counted here rather than skipped in
          // / silence. A source row that quietly evaporates is how a broken transform or a
          // / shifted column survives, because everything downstream still reports success.
          if ($indicatorKind === '' or $indicatorName === '' or $indicatorValue === '') {
            if (!isset($DropCounts[$recipeName.'|the row mapped to an empty kind, name or value'])) $DropCounts[$recipeName.'|the row mapped to an empty kind, name or value'] = 0;
            $DropCounts[$recipeName.'|the row mapped to an empty kind, name or value']++; }
          else {
            if (indicatorIsAcceptable($indicatorKind, $indicatorValue, $recipeName)) {
              $Indicators[] = array('kind' => $indicatorKind, 'name' => $indicatorName, 'value' => $indicatorValue,
                'attributes' => array('src' => $recipeName, 'added' => $BuildDate, 'confidence' => strtolower(trim($recipe['confidence']))));
              // / Remember the riskiest thing accepted, so a build with no refusals still
              // / says how much room it had rather than saying nothing at all.
              $acceptedCount++;
              if ($indicatorKind !== 'md5' && $indicatorKind !== 'sha1' && $indicatorKind !== 'sha256') {
                if ($shortestAccepted === 0 or strlen($indicatorValue) < $shortestAccepted) $shortestAccepted = strlen($indicatorValue);
                if ($indicatorKind === 'data') {
                  redeclare($acceptedEntropy, valueEntropy($indicatorValue));
                  if ($lowestEntropy < 0 or $acceptedEntropy < $lowestEntropy) $lowestEntropy = $acceptedEntropy;
                  // / A run of one repeated byte is measured separately, because entropy is
                  // / capped by length & a short value can look varied while still holding
                  // / a run long enough to match the padding in an ordinary binary.
                  if (longestByteRun($indicatorValue) > $longestAcceptedRun) $longestAcceptedRun = longestByteRun($indicatorValue); } } } } } } }
    // / State the margin on what was accepted. A build reporting no refusals otherwise
    // / tells you nothing about whether it was comfortable or one bad row from trouble.
    if ($shortestAccepted > 0) {
      $marginText = '  Shortest accepted '.$shortestAccepted.' bytes against a minimum of '.(isset($Limits['minlength '.$recipe['kind']]) ? $Limits['minlength '.$recipe['kind']] : 'none').'.';
      if ($lowestEntropy >= 0) {
        // / Name the ceiling as well as the floor. Entropy cannot exceed log2 of the
        // / length, so a short value reporting a low looking figure may in fact be at
        // / its maximum. Reporting the floor alone reads as alarming when it is not.
        $marginText = $marginText.' Least varied '.number_format($lowestEntropy, 2).' bits per byte against a minimum of '.(isset($Limits['minentropy data']) ? $Limits['minentropy data'] : 'none').', where '.number_format(log($shortestAccepted, 2), 2).' is the most a '.$shortestAccepted.' byte value can reach.';
        $marginText = $marginText.' Longest repeated run '.$longestAcceptedRun.' against a maximum of '.(isset($Limits['maxrun data']) ? $Limits['maxrun data'] : 'none').'.'; } }
    buildOutput('Recipe '.$recipeName.' produced '.$acceptedCount.' indicators from '.count($rawLines).' source lines.'.$marginText, 'log', FALSE);
    // / A source with lines in it that yields nothing has a broken mapping, not a quiet day.
    // / Reporting this as an ordinary log line is how a wrong column number survives a year.
    if ($acceptedCount === 0 && count($rawLines) > 0) {
      buildOutput('Recipe '.$recipeName.' produced no indicators at all from '.count($rawLines).' source lines. Check the column mapping in Recipes/'.$recipeName.'.recipe', 'error', TRUE);
      $RecipeYieldFailure = TRUE; } }
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($sourceFile, $rawLines, $rawLine, $skipRemaining, $delimiter, $commentMarker, $rowFields);
  purgeSensitiveMemory($indicatorKind, $indicatorName, $indicatorValue, $acceptedCount, $shortestAccepted, $longestAcceptedRun, $lowestEntropy, $acceptedEntropy, $marginText, $nullValues, $nullEntry, $recipe);
  return $Indicators; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to write one category of indicators to a definition file.
// / Output is sorted & deduplicated, so a rebuild produces a diff a person can review
// / rather than a reshuffle of the whole file.
function writeDefinitionFile($outputFile, $categoryName, $indicators, $attributionList) {
  global $EOL, $BuildDate, $DryRun, $DefsProjectName, $DefsVersion, $DefsFormatVersion, $DefsRepositoryURL;
  // / Set variables.
  $DefinitionsWritten = 0;
  $outputLines = array();
  $seenValues = array();
  $sortKey = '';
  $headerText = '';
  // / Sort by kind then name then value so the ordering never depends on feed order.
  usort($indicators, function($firstIndicator, $secondIndicator) {
    return strcmp($firstIndicator['kind'].'|'.$firstIndicator['name'].'|'.$firstIndicator['value'],
                  $secondIndicator['kind'].'|'.$secondIndicator['name'].'|'.$secondIndicator['value']); });
  foreach ($indicators as $indicatorRecord) {
    redeclare($sortKey, $indicatorRecord['kind'].'|'.strtolower($indicatorRecord['value']));
    // / The same value from two feeds is one indicator, & the first feed named keeps it.
    if (!isset($seenValues[$sortKey])) {
      $seenValues[$sortKey] = TRUE;
      $outputLines[] = formatDefinitionLine($indicatorRecord['kind'], $indicatorRecord['name'], $indicatorRecord['value'], $indicatorRecord['attributes']);
      $DefinitionsWritten++; } }
  // / Stamp the application & the grammar version into the file, so ScanCore can tell
  // / what wrote this & whether it understands the grammar in front of it.
  $headerText = '# ScanCore definitions, '.$categoryName.' category.'.$EOL
    .'# Built by '.$DefsProjectName.' '.$DefsVersion.' on '.$BuildDate.'. Do not edit by hand.'.$EOL
    .'# Definition format: '.$DefsFormatVersion.$EOL
    .'# Source: '.$DefsRepositoryURL.$EOL
    .'# Indicators: '.$DefinitionsWritten.$EOL
    .'#'.$EOL;
  foreach ($attributionList as $attributionLine) $headerText = $headerText.'# '.$attributionLine.$EOL;
  $headerText = $headerText.'#'.$EOL.$EOL;
  if ($DryRun) buildOutput('Would write '.$DefinitionsWritten.' indicators to '.basename($outputFile), 'log', TRUE);
  else {
    if (@file_put_contents($outputFile, $headerText.implode($EOL, $outputLines).$EOL) === FALSE) buildOutput('Cannot write '.$outputFile, 'error', TRUE);
    else buildOutput('Wrote '.$DefinitionsWritten.' indicators to '.basename($outputFile), 'log', TRUE); }
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($outputLines, $seenValues, $sortKey, $headerText, $indicatorRecord, $attributionLine, $indicators);
  return $DefinitionsWritten; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to parse & check a built definition file.
// / This is the same grammar ScanCore itself reads, so a file that verifies here is a
// / file ScanCore can load. A verify failure stops a bad build reaching the repository.
function verifyDefinitionFile($definitionFile) {
  // / Set variables.
  $VerifyPassed = TRUE;
  $rawLines = array();
  $lineNumber = 0;
  $checkedCount = 0;
  $expectedLength = 0;
  $recordKind = $recordValue = '';
  $equalsPosition = 0;
  $validKinds = array('md5', 'sha1', 'sha256', 'name', 'data', 'host', 'url');
  if (!file_exists($definitionFile)) buildOutput('Nothing to verify at '.$definitionFile, 'log', FALSE);
  else {
    $rawLines = file($definitionFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($rawLines)) $rawLines = array();
    foreach ($rawLines as $rawLine) {
      $lineNumber++;
      if (trim($rawLine) !== '' && substr(trim($rawLine), 0, 1) !== '#') {
        redeclare($equalsPosition, strpos($rawLine, '='));
        redeclare($recordKind, strtolower(trim(explode(' ', trim($rawLine))[0])));
        if ($equalsPosition === FALSE) {
          $VerifyPassed = FALSE;
          buildOutput(basename($definitionFile).' line '.$lineNumber.' has no equals sign.', 'error', TRUE); }
        else {
          if (!in_array($recordKind, $validKinds, TRUE)) {
            $VerifyPassed = FALSE;
            buildOutput(basename($definitionFile).' line '.$lineNumber.' names an unknown kind:  '.$recordKind, 'error', TRUE); }
          else {
            $checkedCount++;
            redeclare($recordValue, trim(explode(' ', trim(substr($rawLine, $equalsPosition + 1)))[0]));
            redeclare($expectedLength, 0);
            if ($recordKind === 'md5') $expectedLength = 32;
            if ($recordKind === 'sha1') $expectedLength = 40;
            if ($recordKind === 'sha256') $expectedLength = 64;
            // / A hash that is the wrong length would silently never match anything at all.
            if ($expectedLength > 0) if (!preg_match('/^[0-9a-f]{'.$expectedLength.'}$/', $recordValue)) {
              $VerifyPassed = FALSE;
              buildOutput(basename($definitionFile).' line '.$lineNumber.' is not a whole '.$recordKind.':  '.$recordValue, 'error', TRUE); }
            // / A quoted value has to close, or the parser would swallow the rest of the line.
            if ($expectedLength === 0) if (substr(trim(substr($rawLine, $equalsPosition + 1)), 0, 1) !== '"') {
              $VerifyPassed = FALSE;
              buildOutput(basename($definitionFile).' line '.$lineNumber.' has an unquoted string value.', 'error', TRUE); } } } } }
    buildOutput('Verified '.$checkedCount.' indicators in '.basename($definitionFile).'.', 'log', TRUE); }
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($rawLines, $rawLine, $lineNumber, $checkedCount, $expectedLength, $recordKind, $recordValue, $equalsPosition, $validKinds);
  return $VerifyPassed; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / The main logic of the program.

// / Set variables.
$EOL = PHP_EOL;
$SEP = DIRECTORY_SEPARATOR;
$BuildDate = date('Y-m-d');
$ReportLines = array();
$DropCounts = array();
$Quiet = FALSE;
$DryRun = $DoFetch = $DoBuild = $DoVerify = $Offline = $RecipeYieldFailure = $RedistributableOnly = FALSE;
$OnlyRecipe = '';
$ExitStatus = 0;

// / Refuse to run anywhere except a command line.
if (PHP_SAPI !== 'cli') {
  echo 'ERROR!!!    This builder only runs from a command line interpreter.'.$EOL;
  exit(1); }

// / Load & check the version manifest & the configuration before anything else happens.
// / Neither is optional. A builder running against the wrong half of a release produces
// / a definition file that looks correct & is not, which is worse than not running.
list($ComponentsLoaded, $ComponentFault) = loadDefsComponents($DefsCoreVersion);
if (!$ComponentsLoaded) {
  echo 'ERROR!!!    Cannot start, because '.$ComponentFault.'.'.$EOL;
  echo '            The builder, scancore-defs-version.php & scancore-defs-config.php'.$EOL;
  echo '            are released together. Update all three, or check them out again.'.$EOL;
  exit(1); }
$RepoRoot = $DefsRepoRoot;

// / Process supplied command line arguments.
foreach ($argv as $argKey => $argValue) {
  if ($argValue === '--fetch') $DoFetch = TRUE;
  if ($argValue === '--build') $DoBuild = TRUE;
  if ($argValue === '--verify') $DoVerify = TRUE;
  if ($argValue === '--all') $DoFetch = $DoBuild = $DoVerify = TRUE;
  if ($argValue === '--offline') $Offline = TRUE;
  if ($argValue === '--redistributable-only') $RedistributableOnly = TRUE;
  if ($argValue === '--dry-run') $DryRun = TRUE;
  if ($argValue === '--quiet') $Quiet = TRUE;
  if ($argValue === '--recipe' && isset($argv[$argKey + 1])) $OnlyRecipe = trim($argv[$argKey + 1]); }
if (!$DoFetch && !$DoBuild && !$DoVerify) {
  echo 'Usage:  php Build/scancore-defs.php --all'.$EOL;
  echo '        --fetch --build --verify --offline --dry-run --quiet --recipe <name>'.$EOL;
  echo '        --redistributable-only   handle only sources that may be published'.$EOL;
  echo $EOL.$DefsProjectName.' '.$DefsVersion.', definition format '.$DefsFormatVersion.'.'.$EOL;
  exit(0); }
if ($Offline) $DoFetch = FALSE;

// / Load the policy that governs what an indicator is allowed to be.
$Limits = readSettingsFile($RepoRoot.$SEP.$DefsPolicyDirName.$SEP.$DefsLimitsFileName);
$Allowlist = readAllowlist($RepoRoot.$SEP.$DefsPolicyDirName.$SEP.$DefsAllowlistFileName);
buildOutput('Loaded '.count($Limits).' limits & '.count($Allowlist).' allowlist entries.', 'log', FALSE);

// / Load every recipe, which is where a source declares what it is & what it may become.
$Recipes = array();
$RecipeFiles = glob($RepoRoot.$SEP.$DefsRecipeDirName.$SEP.'*.recipe');
if (!is_array($RecipeFiles)) $RecipeFiles = array();
foreach ($RecipeFiles as $recipeFile) {
  $recipeName = basename($recipeFile, '.recipe');
  if ($OnlyRecipe === '' or $OnlyRecipe === $recipeName) {
    $recipeBody = readSettingsFile($recipeFile);
    // / A recipe that names no license cannot be judged, so it is refused rather than guessed at.
    if (!isset($recipeBody['license']) or trim($recipeBody['license']) === '') buildOutput('Recipe '.$recipeName.' declares no license & was skipped.', 'warning', TRUE);
    else {
      if (isset($recipeBody['enabled']) && strtolower(trim($recipeBody['enabled'])) === 'no') buildOutput('Recipe '.$recipeName.' is disabled & was skipped.', 'log', TRUE);
      else {
        // / A published build never even fetches a source it would not be allowed to publish.
        if ($RedistributableOnly && strtolower(trim($recipeBody['redistribute'])) !== 'yes') buildOutput('Recipe '.$recipeName.' may not be redistributed & was skipped for this build.', 'log', TRUE);
        else $Recipes[$recipeName] = $recipeBody; } } } }
buildOutput('Loaded '.count($Recipes).' enabled recipes.', 'log', TRUE);

// / Fetch each source into Sources, exactly as it arrives.
if ($DoFetch) foreach ($Recipes as $recipeName => $recipeBody) fetchRecipeSource($recipeName, $recipeBody);

// / Build the definition files from whatever is in Sources.
if ($DoBuild) {
  $Categories = array();
  $Attributions = array();
  foreach ($Recipes as $recipeName => $recipeBody) {
    $categoryName = ucfirst(strtolower(trim($recipeBody['category'])));
    // / A source that may not be redistributed is built into Local, which is never committed.
    $redistributable = (strtolower(trim($recipeBody['redistribute'])) === 'yes');
    $categoryKey = ($redistributable ? '' : 'Local:').$categoryName;
    if (!isset($Categories[$categoryKey])) $Categories[$categoryKey] = array();
    if (!isset($Attributions[$categoryKey])) $Attributions[$categoryKey] = array();
    $recipeIndicators = buildRecipeIndicators($recipeName, $recipeBody);
    foreach ($recipeIndicators as $recipeIndicator) $Categories[$categoryKey][] = $recipeIndicator;
    if (count($recipeIndicators) > 0) {
      $Attributions[$categoryKey][] = 'Source '.$recipeName.':  '.trim($recipeBody['license']);
      if (isset($recipeBody['attribution']) && trim($recipeBody['attribution']) !== '') $Attributions[$categoryKey][] = '  '.trim($recipeBody['attribution']); } }
  // / Write each category, keeping the redistributable & local sets strictly apart.
  foreach ($Categories as $categoryKey => $categoryIndicators) {
    if (substr($categoryKey, 0, 6) === 'Local:') {
      if (!is_dir($RepoRoot.$SEP.$DefsLocalDirName)) @mkdir($RepoRoot.$SEP.$DefsLocalDirName, 0755, TRUE);
      $outputFile = $RepoRoot.$SEP.$DefsLocalDirName.$SEP.$DefsOutputPrefix.substr($categoryKey, 6).'.def'; }
    else $outputFile = $RepoRoot.$SEP.$DefsOutputPrefix.$categoryKey.'.def';
    if (count($categoryIndicators) > intval($Limits['maxentries'])) {
      buildOutput('Category '.$categoryKey.' produced '.count($categoryIndicators).' indicators, past the '.$Limits['maxentries'].' limit. Refusing to write it.', 'error', TRUE);
      $ExitStatus = 1; }
    else {
      // / An empty category means every source for it failed, so writing an empty file
      // / would quietly replace a working definition set with nothing at all.
      if (count($categoryIndicators) < 1) buildOutput('Category '.$categoryKey.' produced no indicators, so no file was written.', 'warning', TRUE);
      else writeDefinitionFile($outputFile, $categoryKey, $categoryIndicators, $Attributions[$categoryKey]); } }
  // / Report everything the policy refused, grouped by the reason it was refused for.
  foreach ($DropCounts as $dropKey => $dropCount) buildOutput(str_replace('|', ':  ', $dropKey).'  ('.$dropCount.' indicators)', 'drop', TRUE); }

// / Verify every definition file that the build produced.
if ($DoVerify) {
  $BuiltFiles = array_merge(glob($RepoRoot.$SEP.$DefsOutputPrefix.'*.def') ?: array(), glob($RepoRoot.$SEP.$DefsLocalDirName.$SEP.$DefsOutputPrefix.'*.def') ?: array());
  foreach ($BuiltFiles as $builtFile) if (!verifyDefinitionFile($builtFile)) $ExitStatus = 1;
  // / A recipe that mapped nothing is a build failure, even when every file parses.
  if ($RecipeYieldFailure) $ExitStatus = 1;
  if ($ExitStatus === 0) buildOutput('Every built definition file verified.', 'log', TRUE); }

// / Leave a report behind, because a build that silently drops half a feed is a trap.
if (!$DryRun) @file_put_contents($RepoRoot.$SEP.$DefsBuildReportFileName,
  '# '.$DefsProjectName.' '.$DefsVersion.' build report, '.$BuildDate.'.'.$EOL
  .'# Every line here is something the build refused, changed or could not do.'.$EOL.$EOL
  .(count($ReportLines) > 0 ? implode($EOL, $ReportLines) : 'Nothing was refused or skipped.').$EOL);
exit($ExitStatus);
// / -----------------------------------------------------------------------------------
