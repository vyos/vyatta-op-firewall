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
      * Module: show_firewall_detail.xsl 
      *
      * Author: Mike Horn
      * Date: 2006
      *
      */ -->

<!--XSL Template for formatting the "show firewall <name> detail" command-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:variable name="pad10" select="'           '"/>
<xsl:variable name="pad10_len" select="string-length($pad10)"/>
<xsl:variable name="pad20" select="'                    '"/>
<xsl:variable name="pad20_len" select="string-length($pad20)"/>
<xsl:variable name="pad22" select="'                      '"/>
<xsl:variable name="pad22_len" select="string-length($pad22)"/>
<xsl:variable name="pad34" select="'                                 '"/>
<xsl:variable name="pad34_len" select="string-length($pad34)"/>

<xsl:template match="opcommand">

<xsl:text>&newln;</xsl:text>
<xsl:text>&newln;</xsl:text>

<xsl:for-each select="format/row">

<xsl:text>Rule: </xsl:text>
<xsl:value-of select="rule_number"/>
<xsl:text>&newln;</xsl:text>

<xsl:text>Packets: </xsl:text>
<xsl:value-of select="pkts"/>
<xsl:value-of select="substring($pad10,1,$pad10_len - string-length(pkts))"/>

<xsl:text>Bytes: </xsl:text>
<xsl:value-of select="bytes"/>
<xsl:text>&newln;</xsl:text>

<xsl:text>Action: </xsl:text>
<xsl:value-of select="action"/>
<xsl:text>&newln;</xsl:text>

<xsl:text>Protocol: </xsl:text>
<xsl:value-of select="protocol"/>
<xsl:text>&newln;</xsl:text>

<xsl:text>State: </xsl:text>
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

<xsl:text>Source</xsl:text>
<xsl:text>&newln;</xsl:text>
<xsl:text>  Address: </xsl:text>
  <xsl:choose>
    <xsl:when test="src_addr!='' and src_addr!='0.0.0.0'">
      <xsl:value-of select="src_addr"/>
    </xsl:when>

    <xsl:when test="src_net!='' and src_net!='0.0.0.0/0'">
      <xsl:value-of select="src_net"/>
    </xsl:when>

    <xsl:when test="src_addr_start!='' and src_addr_start!='0.0.0.0'">
      <xsl:value-of select="src_addr_start"/>
      <xsl:text> - </xsl:text>
      <xsl:value-of select="src_addr_stop"/>
    </xsl:when>

    <xsl:otherwise>
      <xsl:text>0.0.0.0/0</xsl:text>
    </xsl:otherwise>
  </xsl:choose>
<xsl:text>&newln;</xsl:text>
<xsl:text>  Ports: </xsl:text>

  <xsl:choose>
    <xsl:when test="src_port!=''">
      <xsl:value-of select="src_port"/>
    </xsl:when>

    <xsl:otherwise>
      <xsl:text>all</xsl:text>
    </xsl:otherwise>
  </xsl:choose>

<xsl:text>&newln;</xsl:text>
<xsl:text>Destination</xsl:text>
<xsl:text>&newln;</xsl:text>
<xsl:text>  Address: </xsl:text>
  <xsl:choose>
    <xsl:when test="dst_addr!='' and dst_addr!='0.0.0.0'">
      <xsl:value-of select="dst_addr"/>
    </xsl:when>

    <xsl:when test="dst_net!='' and dst_net!='0.0.0.0/0'">
      <xsl:value-of select="dst_net"/>
    </xsl:when>

    <xsl:when test="dst_addr_start!='' and dst_addr_start!='0.0.0.0'">
      <xsl:value-of select="dst_addr_start"/>
      <xsl:text> - </xsl:text>
      <xsl:value-of select="dst_addr_stop"/>
    </xsl:when>

    <xsl:otherwise>
      <xsl:text>0.0.0.0/0</xsl:text>
    </xsl:otherwise>
  </xsl:choose>
<xsl:text>&newln;</xsl:text>
<xsl:text>  Ports: </xsl:text>

  <xsl:choose>
    <xsl:when test="dst_port!=''">
      <xsl:value-of select="dst_port"/>
    </xsl:when>

    <xsl:otherwise>
      <xsl:text>all</xsl:text>
    </xsl:otherwise>
  </xsl:choose>

<xsl:text>&newln;</xsl:text>

<xsl:text>ICMP Code: </xsl:text>
  <xsl:if test="icmp_code=''">
    <xsl:text>-</xsl:text>
  </xsl:if> 
  <xsl:if test="icmp_code!=''">
    <xsl:value-of select="icmp_code"/>
  </xsl:if> 

<xsl:text>&newln;</xsl:text>

<xsl:text>ICMP Type: </xsl:text>
  <xsl:if test="icmp_type=''">
    <xsl:text>-</xsl:text>
  </xsl:if> 
  <xsl:if test="icmp_type!=''">
    <xsl:value-of select="icmp_type"/>
  </xsl:if> 

<xsl:text>&newln;</xsl:text>
<xsl:text>Logging: </xsl:text>
<xsl:value-of select="log"/>

<xsl:text>&newln;</xsl:text>
  <xsl:if test="rule_number!='10000'">
    <xsl:text>------------------------</xsl:text>
    <xsl:text>&newln;</xsl:text>
  </xsl:if>

</xsl:for-each>
</xsl:template>

</xsl:stylesheet>
