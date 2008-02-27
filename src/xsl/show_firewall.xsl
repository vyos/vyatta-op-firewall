<?xml version="1.0"?>
<!DOCTYPE stylesheet [
<!ENTITY newln "&#10;">
]>

<!-- /*
      *  Copyright 2006, Vyatta, Inc.
      *
      *  GNU General Public License
      *
      *  This program is free software; you can redistribute it and/or modify
      *  it under the terms of the GNU General Public License, version 2,
      *  as published by the Free Software Foundation.
      *
      *  This program is distributed in the hope that it will be useful,
      *  but WITHOUT ANY WARRANTY; without even the implied warranty of
      *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
      *  GNU General Public License for more details.
      *
      *  You should have received a copy of the GNU General Public License
      *  along with this program; if not, write to the Free Software
      *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
      *  02110-1301 USA
      *
      * Module: show_firewall.xsl 
      *
      * Author: Mike Horn
      * Date: 2006
      *
      */ -->

<!--XSL Template for formatting the "show firewall <name>" command-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:variable name="pad6" select="'      '"/>
<xsl:variable name="pad6_len" select="string-length($pad6)"/>
<xsl:variable name="pad7" select="'       '"/>
<xsl:variable name="pad7_len" select="string-length($pad7)"/>
<xsl:variable name="pad8" select="'        '"/>
<xsl:variable name="pad8_len" select="string-length($pad8)"/>
<xsl:variable name="pad20" select="'                    '"/>
<xsl:variable name="pad20_len" select="string-length($pad20)"/>

<xsl:comment> FORMAT HEADER LINES </xsl:comment>

<xsl:template match="opcommand">
<xsl:text>&newln;</xsl:text>
<xsl:text>&newln;</xsl:text>
<xsl:text>State Codes: E - Established, I - Invalid, N - New, R - Related&newln;</xsl:text>
<xsl:text>&newln;</xsl:text>
<xsl:text>rule  action  source              destination         proto  state</xsl:text>
<xsl:text>&newln;</xsl:text>
<xsl:text>----  ------  ------              -----------         -----  ----- </xsl:text>
<xsl:text>&newln;</xsl:text>

<xsl:for-each select="format/row">

<xsl:value-of select="rule_number"/>
<xsl:value-of select="substring($pad6,1,$pad6_len - string-length(rule_number))"/>

<xsl:value-of select="action"/>
<xsl:value-of select="substring($pad8,1,$pad8_len - string-length(action))"/>

  <xsl:choose>
    <xsl:when test="src_addr!='' and src_addr!='0.0.0.0'">
      <xsl:value-of select="src_addr"/>
      <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(src_addr))"/>
    </xsl:when>
    
    <xsl:when test="src_net!='' and src_addr!='0.0.0.0/0'">
      <xsl:value-of select="src_net"/>
      <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(src_net))"/>
    </xsl:when>

    <xsl:when test="src_addr_start!='' and src_addr_start!='0.0.0.0'">
      <xsl:text>Range (use detail)  </xsl:text>
    </xsl:when>

    <xsl:otherwise>
      <xsl:text>0.0.0.0/0</xsl:text>
      <xsl:value-of select="substring($pad20,1,$pad20_len - 9)"/>
    </xsl:otherwise>
  </xsl:choose>

  <xsl:choose>
    <xsl:when test="dst_addr!='' and dst_addr!='0.0.0.0'">
      <xsl:value-of select="dst_addr"/>
      <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(dst_addr))"/>
    </xsl:when>
    
    <xsl:when test="dst_net!='' and dst_addr!='0.0.0.0/0'">
      <xsl:value-of select="dst_net"/>
      <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(dst_net))"/>
    </xsl:when>

    <xsl:when test="dst_addr_start!='' and dst_addr_start!='0.0.0.0'">
      <xsl:text>Range (use detail)  </xsl:text>
    </xsl:when>

    <xsl:otherwise>
      <xsl:text>0.0.0.0/0</xsl:text>
      <xsl:value-of select="substring($pad20,1,$pad20_len - 9)"/>
    </xsl:otherwise>
  </xsl:choose>

<xsl:value-of select="protocol"/>
<xsl:value-of select="substring($pad7,1,$pad7_len - string-length(protocol))"/>

  <xsl:choose>
    <xsl:when test="contains(state, 'established%2C')">
      <xsl:text>E,</xsl:text>
    </xsl:when>
    <xsl:when test="contains(state, 'established')">
      <xsl:text>E</xsl:text>
    </xsl:when>
  </xsl:choose>
  <xsl:choose>
    <xsl:when test="contains(state, 'new%2C')">
      <xsl:text>N,</xsl:text>
    </xsl:when>
    <xsl:when test="contains(state, 'new')">
      <xsl:text>N</xsl:text>
    </xsl:when>
  </xsl:choose>
  <xsl:choose>
    <xsl:when test="contains(state, 'related%2C')">
      <xsl:text>R,</xsl:text>
    </xsl:when>
    <xsl:when test="contains(state, 'related')">
      <xsl:text>R</xsl:text>
    </xsl:when>
  </xsl:choose>
  <xsl:choose>
    <xsl:when test="contains(state, 'invalid%2C')">
      <xsl:text>I,</xsl:text>
    </xsl:when>
    <xsl:when test="contains(state, 'invalid')">
      <xsl:text>I</xsl:text>
    </xsl:when>
  </xsl:choose>
  <xsl:choose>
    <xsl:when test="state=''">
      <xsl:text>any</xsl:text>
    </xsl:when>
  </xsl:choose>

  <xsl:text>&newln;</xsl:text>

  <xsl:if test="src_port!=''">
    <xsl:value-of select="$pad6"/>
    <xsl:value-of select="$pad8"/>
    <xsl:text>src ports: </xsl:text>
    <xsl:value-of select="src_port"/>

    <xsl:text>&newln;</xsl:text>
  </xsl:if>
  
  <xsl:if test="dst_port!=''">
    <xsl:value-of select="$pad6"/>
    <xsl:value-of select="$pad8"/>
    <xsl:value-of select="$pad20"/>
    <xsl:text>dst ports: </xsl:text>
    <xsl:value-of select="dst_port"/>

    <xsl:text>&newln;</xsl:text>
  </xsl:if>

</xsl:for-each>
</xsl:template>

</xsl:stylesheet>
