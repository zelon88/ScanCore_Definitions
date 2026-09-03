<?php
// / -----------------------------------------------------------------------------------
// / COPYRIGHT INFORMATION ...
// / ScanCore Definitions, Copyright 2026 by Justin Grimes, www.github.com/zelon88
// / 
// / LICENSE INFORMATION ...
// / This project is protected by the GNU GPLv3 Open-Source license.
// / https://www.gnu.org/licenses/gpl-3.0.html
// / 
// / FILE INFORMATION ...
// / v1.8.
// / This file collects raw threat feeds & builds them into ScanCore definition files.
// / 
// / WHAT THIS DOES ...
// / A recipe describes one source. Where to fetch it, how to read it & what it may
// / become. The raw download is kept in Sources exactly as it arrived, so a build is
// / always reproducible from committed data & a bad feed can be traced afterwards.
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
// /   Work on one recipe only:                --recipe <name>
// /   Never touch the network:                --offline
// /   Explain what would happen, change none: --dry-run
// / 
// / <3 Open-Source
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
  $minimumLength = $maximumLength = 0;
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
  purgeSensitiveMemory($refusalReason, $hostName, $expectedLength, $minimumLength, $maximumLength, $allowedHost);
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
  if ($indicatorKind !== 'md5' && $indicatorKind !== 'sha1' && $indicatorKind !== 'sha256') $renderedValue = '"'.str_replace('"', '\\"', $indicatorValue).'"';
  foreach ($attributes as $attributeKey => $attributeValue) if ($attributeValue !== '') $attributeText = $attributeText.' '.$attributeKey.'='.$attributeValue;
  $DefinitionLine = sprintf('%-6s %-44s = %s%s', $indicatorKind, $indicatorName, $renderedValue, $attributeText);
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($renderedValue, $attributeText, $attributeKey, $attributeValue, $attributes);
  return $DefinitionLine; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to download one recipe source into the Sources directory.
// / The download is written exactly as it arrived. Nothing is reformatted here, so a
// / build is always reproducible from what is committed & a bad feed stays traceable.
function fetchRecipeSource($recipeName, $recipe) {
  global $RepoRoot, $SEP, $DryRun;
  // / Set variables.
  $SourceFetched = FALSE;
  $sourceFile = $RepoRoot.$SEP.'Sources'.$SEP.basename($recipe['file']);
  $stagedFile = $sourceFile.'.new';
  $streamContext = NULL;
  $headerText = '';
  $fetchedData = FALSE;
  $authValue = '';
  // / A recipe with no url describes a file that is maintained by hand.
  if (!isset($recipe['url']) or trim($recipe['url']) === '') {
    buildOutput('Recipe '.$recipeName.' has no url, so its source file is used as it stands.', 'log', FALSE);
    $SourceFetched = file_exists($sourceFile); }
  else {
    // / Supply an authentication header when the recipe names an environment variable.
    if (isset($recipe['authenv']) && trim($recipe['authenv']) !== '') {
      $authValue = strval(getenv(trim($recipe['authenv'])));
      if ($authValue === '') buildOutput('Recipe '.$recipeName.' needs '.$recipe['authenv'].' in the environment & it is not set.', 'warning', TRUE);
      else $headerText = trim($recipe['authheader']).': '.$authValue."\r\n"; }
    if ($DryRun) {
      buildOutput('Would fetch '.$recipeName.' from '.$recipe['url'], 'log', TRUE);
      $SourceFetched = file_exists($sourceFile); }
    else {
      $streamContext = stream_context_create(array('http' => array('timeout' => 60, 'follow_location' => 1, 'user_agent' => 'ScanCore-Definitions-Builder', 'header' => $headerText)));
      $fetchedData = @file_get_contents(trim($recipe['url']), FALSE, $streamContext);
      if (!is_string($fetchedData) or trim($fetchedData) === '') buildOutput('Cannot fetch '.$recipeName.' from '.$recipe['url'], 'error', TRUE);
      else {
        // / Stage the download & only replace the committed source once it has arrived whole.
        if (@file_put_contents($stagedFile, $fetchedData) === FALSE) buildOutput('Cannot stage the download for '.$recipeName, 'error', TRUE);
        else {
          if (file_exists($sourceFile)) @unlink($sourceFile);
          $SourceFetched = @rename($stagedFile, $sourceFile);
          if ($SourceFetched) buildOutput('Fetched '.$recipeName.', '.strlen($fetchedData).' bytes.', 'log', FALSE); } } } }
  if (file_exists($stagedFile)) @unlink($stagedFile);
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($sourceFile, $stagedFile, $streamContext, $headerText, $fetchedData, $authValue, $recipe);
  return $SourceFetched; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to turn one recipe & its raw source into a list of definition records.
function buildRecipeIndicators($recipeName, $recipe) {
  global $RepoRoot, $SEP, $BuildDate;
  // / Set variables.
  $Indicators = array();
  $sourceFile = $RepoRoot.$SEP.'Sources'.$SEP.basename($recipe['file']);
  $rawLines = array();
  $skipRemaining = 0;
  $delimiter = ',';
  $commentMarker = '#';
  $rowFields = array();
  $indicatorKind = $indicatorName = $indicatorValue = '';
  $acceptedCount = 0;
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
          redeclare($indicatorValue, resolveRecipeField($recipe['value'], $rowFields));
          // / A hash is stored lower case so an exact comparison never depends on casing.
          if ($indicatorKind === 'md5' or $indicatorKind === 'sha1' or $indicatorKind === 'sha256') $indicatorValue = strtolower($indicatorValue);
          if ($indicatorKind !== '' && $indicatorName !== '' && $indicatorValue !== '') {
            if (indicatorIsAcceptable($indicatorKind, $indicatorValue, $recipeName)) {
              $Indicators[] = array('kind' => $indicatorKind, 'name' => $indicatorName, 'value' => $indicatorValue,
                'attributes' => array('src' => $recipeName, 'added' => $BuildDate, 'confidence' => strtolower(trim($recipe['confidence']))));
              $acceptedCount++; } } } } }
    buildOutput('Recipe '.$recipeName.' produced '.$acceptedCount.' indicators from '.count($rawLines).' source lines.', 'log', FALSE); }
  // / Manually clean up sensitive memory. Helps to keep track of variable assignments.
  purgeSensitiveMemory($sourceFile, $rawLines, $rawLine, $skipRemaining, $delimiter, $commentMarker, $rowFields);
  purgeSensitiveMemory($indicatorKind, $indicatorName, $indicatorValue, $acceptedCount, $recipe);
  return $Indicators; }
// / -----------------------------------------------------------------------------------

// / -----------------------------------------------------------------------------------
// / A function to write one category of indicators to a definition file.
// / Output is sorted & deduplicated, so a rebuild produces a diff a person can review
// / rather than a reshuffle of the whole file.
function writeDefinitionFile($outputFile, $categoryName, $indicators, $attributionList) {
  global $EOL, $BuildDate, $DryRun;
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
  $headerText = '# ScanCore definitions, '.$categoryName.' category.'.$EOL
    .'# Built by Build/scancore-defs.php on '.$BuildDate.'. Do not edit by hand.'.$EOL
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
$RepoRoot = realpath(dirname(dirname(__FILE__)));
$BuildDate = date('Y-m-d');
$ReportLines = array();
$DropCounts = array();
$Quiet = FALSE;
$DryRun = $DoFetch = $DoBuild = $DoVerify = $Offline = FALSE;
$OnlyRecipe = '';
$ExitStatus = 0;

// / Refuse to run anywhere except a command line.
if (PHP_SAPI !== 'cli') {
  echo 'ERROR!!!    This builder only runs from a command line interpreter.'.$EOL;
  exit(1); }

// / Process supplied command line arguments.
foreach ($argv as $argKey => $argValue) {
  if ($argValue === '--fetch') $DoFetch = TRUE;
  if ($argValue === '--build') $DoBuild = TRUE;
  if ($argValue === '--verify') $DoVerify = TRUE;
  if ($argValue === '--all') $DoFetch = $DoBuild = $DoVerify = TRUE;
  if ($argValue === '--offline') $Offline = TRUE;
  if ($argValue === '--dry-run') $DryRun = TRUE;
  if ($argValue === '--quiet') $Quiet = TRUE;
  if ($argValue === '--recipe' && isset($argv[$argKey + 1])) $OnlyRecipe = trim($argv[$argKey + 1]); }
if (!$DoFetch && !$DoBuild && !$DoVerify) {
  echo 'Usage:  php Build/scancore-defs.php --all'.$EOL;
  echo '        --fetch --build --verify --offline --dry-run --quiet --recipe <name>'.$EOL;
  exit(0); }
if ($Offline) $DoFetch = FALSE;

// / Load the policy that governs what an indicator is allowed to be.
$Limits = readSettingsFile($RepoRoot.$SEP.'Policy'.$SEP.'limits.txt');
$Allowlist = readAllowlist($RepoRoot.$SEP.'Policy'.$SEP.'allowlist.txt');
buildOutput('Loaded '.count($Limits).' limits & '.count($Allowlist).' allowlist entries.', 'log', FALSE);

// / Load every recipe, which is where a source declares what it is & what it may become.
$Recipes = array();
$RecipeFiles = glob($RepoRoot.$SEP.'Recipes'.$SEP.'*.recipe');
if (!is_array($RecipeFiles)) $RecipeFiles = array();
foreach ($RecipeFiles as $recipeFile) {
  $recipeName = basename($recipeFile, '.recipe');
  if ($OnlyRecipe === '' or $OnlyRecipe === $recipeName) {
    $recipeBody = readSettingsFile($recipeFile);
    // / A recipe that names no license cannot be judged, so it is refused rather than guessed at.
    if (!isset($recipeBody['license']) or trim($recipeBody['license']) === '') buildOutput('Recipe '.$recipeName.' declares no license & was skipped.', 'warning', TRUE);
    else {
      if (isset($recipeBody['enabled']) && strtolower(trim($recipeBody['enabled'])) === 'no') buildOutput('Recipe '.$recipeName.' is disabled & was skipped.', 'log', TRUE);
      else $Recipes[$recipeName] = $recipeBody; } } }
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
      if (!is_dir($RepoRoot.$SEP.'Local')) @mkdir($RepoRoot.$SEP.'Local', 0755, TRUE);
      $outputFile = $RepoRoot.$SEP.'Local'.$SEP.'ScanCore_'.substr($categoryKey, 6).'.def'; }
    else $outputFile = $RepoRoot.$SEP.'ScanCore_'.$categoryKey.'.def';
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
  $BuiltFiles = array_merge(glob($RepoRoot.$SEP.'ScanCore_*.def') ?: array(), glob($RepoRoot.$SEP.'Local'.$SEP.'ScanCore_*.def') ?: array());
  foreach ($BuiltFiles as $builtFile) if (!verifyDefinitionFile($builtFile)) $ExitStatus = 1;
  if ($ExitStatus === 0) buildOutput('Every built definition file verified.', 'log', TRUE); }

// / Leave a report behind, because a build that silently drops half a feed is a trap.
if (!$DryRun) @file_put_contents($RepoRoot.$SEP.'BUILD_REPORT.txt',
  '# ScanCore definition build report, '.$BuildDate.'.'.$EOL
  .'# Every line here is something the build refused, changed or could not do.'.$EOL.$EOL
  .(count($ReportLines) > 0 ? implode($EOL, $ReportLines) : 'Nothing was refused or skipped.').$EOL);
exit($ExitStatus);
// / -----------------------------------------------------------------------------------
