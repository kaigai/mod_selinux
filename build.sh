#!/bin/sh

NAME=mod_selinux
BASEDIR=`dirname "$0"` || exit 1
WORKDIR=`mktemp -d` || exit 1
RPMSOURCE=`rpm -E %{_sourcedir}` || exit 1
REVISION=`env LANG=C svn info ${BASEDIR}/* 2>/dev/null \
    | grep '^Last Changed Rev' | awk '{print $4}' | sort | tail -1`

cat ${BASEDIR}/${NAME}.spec				\
    | sed "s/%%__${NAME}_revision__%%/${REVISION}/g"	\
    > ${RPMSOURCE}/${NAME}.spec

VERSION=`rpm -q --queryformat='%{version}\n' --specfile ${RPMSOURCE}/${NAME}.spec | head -1`

mkdir -p ${WORKDIR}/${NAME}-${VERSION} || exit 1
cp -f ${BASEDIR}/${NAME}.c	\
    ${BASEDIR}/${NAME}.te	\
    ${BASEDIR}/${NAME}.if	\
    ${BASEDIR}/Makefile		\
    ${BASEDIR}/modules.mk	\
    ${BASEDIR}/.deps		\
    ${BASEDIR}/LICENSE		\
    ${BASEDIR}/README		\
    ${WORKDIR}/${NAME}-${VERSION}
(cd ${WORKDIR}; tar zc ${NAME}-${VERSION}) \
    > ${RPMSOURCE}/${NAME}-${VERSION}.tgz

rm -rf ${WORKDIR}

cp -f ${BASEDIR}/${NAME}.conf	${RPMSOURCE}
# cp -f ${BASEDIR}/${NAME}.map	${RPMSOURCE}

rpmbuild -ba ${RPMSOURCE}/${NAME}.spec

echo "tarball: ${RPMSOURCE}/${NAME}-${VERSION}.tgz"