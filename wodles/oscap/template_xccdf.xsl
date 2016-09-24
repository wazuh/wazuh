<?xml version="1.0" encoding="UTF-8"?>
<stylesheet version="1.0" xmlns="http://www.w3.org/1999/XSL/Transform">
    <output method="text" omit-xml-declaration="yes" indent="no"/>
    <template match="/">
      <for-each select="*[local-name()='Benchmark']/*[local-name()='TestResult']">
        <for-each select="*[local-name()='rule-result']" xml:space="preserve">oscap: msg: "xccdf-result", title: "<value-of select="translate(/*[local-name()='Benchmark']//*[local-name()='Rule'][@id=current()/@idref]/*[local-name()='title'], '&#xA;', ' ')"/>", benchmark: "<value-of select="/*[local-name()='Benchmark']/*[local-name()='TestResult']/*[local-name()='benchmark']/@id" />", profile: "<value-of select="/*[local-name()='Benchmark']/*[local-name()='TestResult']/*[local-name()='profile']/@idref" />", severity: "<value-of select="@severity"/>", result: "<value-of select="*[local-name()='result']"/>", id: "<value-of select="@idref"/>", oval: "<value-of select="*[local-name()='check']/*[local-name()='check-content-ref']/@name"/>", reference: "<for-each select="*[local-name()='ident']"><if test="position() > 1">,</if><value-of select="."/></for-each>".<text>
</text></for-each></for-each>oscap: msg: "xccdf-overview", benchmark: "<value-of select="/*[local-name()='Benchmark']/*[local-name()='TestResult']/*[local-name()='benchmark']/@id" />", profile: "<value-of select="/*[local-name()='Benchmark']/*[local-name()='TestResult']/*[local-name()='profile']/@idref" />", score: "<value-of select="*[local-name()='Benchmark']/*[local-name()='TestResult']/*[local-name()='score']" />".
</template>
</stylesheet>
