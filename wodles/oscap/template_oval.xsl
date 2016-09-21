<?xml version="1.0" encoding="UTF-8"?>
<stylesheet version="1.0" xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:r="http://oval.mitre.org/XMLSchema/oval-results-5" xmlns:d="http://oval.mitre.org/XMLSchema/oval-definitions-5">
    <output method="text" omit-xml-declaration="yes" indent="no"/>
    <template match="/">
      <for-each select="r:oval_results/r:results//r:definition">oscap: msg: "oval-result", id: "<value-of select="@definition_id" />", title: "<value-of select="translate(/r:oval_results/d:oval_definitions/d:definitions/d:definition[@id=current()/@definition_id]/d:metadata/d:title, '&#xA;', ' ')" />", class: "<value-of select="/r:oval_results/d:oval_definitions/d:definitions/d:definition[@id=current()/@definition_id]/@class" />", result: "<value-of select="@result" />", reference: "<for-each select="/r:oval_results/d:oval_definitions/d:definitions/d:definition[@id=current()/@definition_id]/d:metadata/d:reference" ><if test="position() > 1">,</if><value-of select="@ref_id" /></for-each>".
</for-each>
</template>
</stylesheet>
