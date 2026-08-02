// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "PjHandle.h"
#include <rz_util.h>

PjHandle::PjHandle()
	: m_pj(pj_new())
{
}

PjHandle::~PjHandle()
{
	if (m_pj) {
		pj_free(m_pj);
	}
}

PjHandle::PjHandle(PjHandle &&other) noexcept
	: m_pj(other.m_pj)
{
	other.m_pj = nullptr;
}

PjHandle &PjHandle::operator=(PjHandle &&other) noexcept
{
	if (this != &other) {
		if (m_pj) {
			pj_free(m_pj);
		}
		m_pj = other.m_pj;
		other.m_pj = nullptr;
	}
	return *this;
}

char *PjHandle::drain()
{
	PJ *pj = m_pj;
	m_pj = nullptr;
	if (!pj) {
		return nullptr;
	}
	return pj_drain(pj);
}
