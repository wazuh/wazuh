<?xml version="1.0" encoding="UTF-8"?>
<stylesheet version="1.0" xmlns="http://www.w3.org/1999/XSL/Transform">
    <output method="text" omit-xml-declaration="yes" indent="no"/>
    <template match="/">
benchmark:<value-of select="/*[local-name()='Benchmark']/*[local-name()='TestResult']/*[local-name()='title']"/>
    <variable name="profile-id" select="/*[local-name()='Benchmark']/*[local-name()='TestResult']/*[local-name()='profile']/@idref"/>
profile_title:<value-of select="/*[local-name()='Benchmark']/*[local-name()='Profile'][@id=$profile-id]/*[local-name()='title']"/>
hostname:<value-of select="/*[local-name()='Benchmark']/*[local-name()='TestResult']/*[local-name()='target']"/>
timestamp:<value-of select="/*[local-name()='Benchmark']/*[local-name()='TestResult']/@end-time"/>
score:<value-of select="/*[local-name()='Benchmark']/*[local-name()='TestResult']/*[local-name()='score']"/>
      <for-each select="*[local-name()='Benchmark']//*[local-name()='Group']">
          <variable name="group-title" select="*[local-name()='title']" />
          <for-each select="//*[local-name()='Rule']">
<variable name="rule-id" select="@id"/>
<variable name="rule-title" select="*[local-name()='title']"/>
********
rule_id:<value-of select="$rule-id"/>
rule_title:<value-of select="$rule-title"/>
group:<value-of select="$group-title"/>
description:<for-each select="*[local-name()='description']"><value-of select="normalize-space(*[local-name()='p'])"/></for-each>
rationale:<for-each select="*[local-name()='rationale']"><value-of select="normalize-space(*[local-name()='p'])"/></for-each>
remediation:<for-each select="*[local-name()='fixtext']"><value-of select="normalize-space(*[local-name()='div']/*[local-name()='p'])"/></for-each>
result:<value-of select="//*[local-name()='rule-result'][@idref=$rule-id]/*[local-name()='result']"/></for-each></for-each>
********
</template>
</stylesheet>
