// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#pragma once

typedef struct pj_t PJ;

/**
 * \brief RAII handle for a rizin PJ (JSON builder).
 *
 * Owns a pj_new() alloc, destructor calls pj_free() on
 * early return paths before PJ is drained.  drain() releases
 * ownership (pj_drain frees PJ and returns its buffer), so
 * destructor is nop after drain.
 *
 * move only, as copy will double free.
 */
class PjHandle {
public:
	PjHandle();
	~PjHandle();

	PjHandle(const PjHandle &) = delete;
	PjHandle &operator=(const PjHandle &) = delete;
	PjHandle(PjHandle &&other) noexcept;
	PjHandle &operator=(PjHandle &&other) noexcept;

	explicit operator bool() const { return m_pj != nullptr; }
	PJ *get() const { return m_pj; }
	char *drain();

private:
	PJ *m_pj;
};
