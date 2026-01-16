/*
 * Mojo Compatibility Stubs
 * Provides implementations for functions declared in openwebos/db8 headers
 * but not present in webOS 3.0.5 libmojocore.so
 */

#include "core/MojCoreDefs.h"
#include "core/MojObject.h"
#include "core/MojSignal.h"

/*
 * MojObject::release()
 * Called from ~MojObject() destructor
 * Releases the implementation pointer
 */
void MojObject::release()
{
    if (m_implementation) {
        // The implementation is reference counted
        // For webOS 3.0.5 compatibility, we just need to handle cleanup
        // The actual MojObject::Impl class has its own ref counting
        m_implementation = NULL;
    }
}

/*
 * MojSignalHandler destructor
 * Base class for signal handlers
 */
MojSignalHandler::~MojSignalHandler()
{
    // Base destructor - cleanup is handled by derived classes
}
