
// Show function ref count plug-in.
#include "StdAfx.h"
#include <list>
#include <WaitBoxEx.h>
#include <SegSelect.h>

const static WORD PROCESS_FUNCTIONS = (1 << 0);
const static WORD PROCESS_DATA = (1 << 1);

static const char SITE_URL[] = { "https://github.com/kweatherman/IDA_MarkRefCount_PlugIn" };

static void processFunction(func_t *f);
static void processDataItem(ea_t address);

static BOOL processFunctions = TRUE;
static BOOL processData      = TRUE;
static SegSelect::segments dataSegs;

// Main dialog
static const char optionDialog[] =
{
	"BUTTON YES* Continue\n" // "Continue" instead of an "okay" button

	// Title
	"Mark Reference Counts\n"
    #ifdef _DEBUG
    "** DEBUG BUILD **\n"
    #endif

	// Message text
    "-Version %Aby Sirmabus-\n"
    "<#Click to open site.#MarkRefCount Github:k:2:1::>\n\n"
	"Creates new or prefixes exiting comments with function references, \nand, or, data xrefs-to-code counts.\n\n"

	// ** Order must match option bit flags above
	"Processing options:\n"
	"<#Add reference counts to all functions.#Do function references.                                             :C>\n"
    "<#Add references counts to all data-to-code references that are greater then one.#Do data references.:C>>\n"	
	" \n"

	"<#Choose the data segments to scan.\nElse will use default 'DATA' segments by default.#Choose DATA segments:B:2:19::>\n \n"
};


// Initialize
plugmod_t* idaapi init()
{
	return PLUGIN_OK;
}

void idaapi term()
{
}

static void idaapi doHyperlink(int button_code, form_actions_t &fa) { open_url(SITE_URL); }

// Handler for choose code data segment button
static void idaapi chooseBtnHandler(int button_code, form_actions_t &fa)
{
    SegSelect::select(dataSegs, (SegSelect::DATA_HINT | SegSelect::RDATA_HINT), "Choose data segments");
}

// Plug-in process
bool idaapi run(size_t arg)
{
	qstring version;
	msg("\n>> Mark Reference Counts: v%s, built %s.\n", GetVersionString(MY_VERSION, version).c_str(), __DATE__);

	if (!auto_is_ok())
	{
		warning("Auto-analysis must finish first before you run this plug-in!");
		msg("\n** Aborted **\n");
		goto exit;
	}

	try
	{
		dataSegs.clear();
		WORD optionFlags = 0;
		if (processFunctions) optionFlags |= PROCESS_FUNCTIONS;
		if (processData)	  optionFlags |= PROCESS_DATA;

		int result = ask_form(optionDialog, version.c_str(), doHyperlink, &optionFlags, chooseBtnHandler);
		if (!result)
		{
			msg(" - Canceled -\n");
			goto exit;
		}
		processFunctions = ((optionFlags & PROCESS_FUNCTIONS) > 0);
		processData = ((optionFlags & PROCESS_DATA) > 0);

		TIMESTAMP startTime = GetTimeStamp();
		WaitBox::show();
		WaitBox::updateAndCancelCheck(-1);
		BOOL aborted = FALSE;

		if (processData)
		{
			// Use data segment defaults if none selected
			if (dataSegs.empty())
			{
				int segCount = get_segm_qty();
				for (int i = 0; i < segCount; i++)
				{
					if (segment_t* seg = getnseg(i))
					{
						if (seg->type == SEG_DATA)
							dataSegs.push_back(*seg);
					}
				}
			}

			// Verify there are data segments to process
			if (dataSegs.empty())
			{
				msg("\nNo data segments found or selected!\n");
				msg("* Aborted *\n");
				goto exit;
			}
		}

		if (processFunctions)
		{
			// Iterate through functions..
			UINT functionCount = (UINT) get_func_qty();
			char buffer[32];
			msg("Processing %s functions.\n", NumberCommaString(functionCount, buffer));

			for (UINT i = 0; i < functionCount; i++)
			{
				processFunction(getn_func(i));

				if (i % 500)
				{
					if (WaitBox::isUpdateTime())
					{
						if (WaitBox::updateAndCancelCheck())
						{
							msg("* Aborted *\n\n");
							aborted = TRUE;
							break;
						}
					}
				}
			}
		}

		if (!aborted && processData)
		{
			// Iterate through data segments
			for (const auto &seg: dataSegs)
			{
				qstring name;
				get_segm_name(&name, &seg);
				msg("Processing data segment: \"%s\" %llX - %llX\n", name.c_str(), seg.start_ea, seg.end_ea);

				ea_t  startEA = seg.start_ea;
				ea_t  endEA   = seg.end_ea;
				ea_t address  = startEA;
				int index = 0;

				while (address <= endEA)
				{
					processDataItem(address);
					if ((address = next_addr(address)) == BADADDR)
						break;

					if (index % 500)
					{
						if (WaitBox::isUpdateTime())
						{
							if (WaitBox::updateAndCancelCheck())
							{
								msg("* Aborted *\n\n");
								aborted = TRUE;
								break;
							}
						}
					}
					index++;
				};
			}
		}

		if (!aborted && (processFunctions || processData))				
			msg("Done. Took %s.\n", TimeString(GetTimeStamp() - startTime));
	}
	CATCH();

	exit:;
	dataSegs.clear();
	refresh_idaview_anyway();
    WaitBox::hide();
	return true;
}


// Process function
static void processFunction(func_t *f)
{
	xrefblk_t xb;
	if(xb.first_to(f->start_ea, XREF_ALL))
	{
		// Per IDA doc code refs come first, then data refs
		if(xb.type >= fl_CF)
		{
			UINT count = 1;
			while(xb.next_to())
			{
				// Break on first data ref
				if(xb.type >= fl_CF)
					count++;
				else
					break;
			};

			// If there is more than 1 count
			if (count > 1)
			{
				// Append to existing comment if it exists
				char cmt[MAXSTR];
				qstring current;
				if (get_func_cmt(&current, f, true) > 0)				
					_snprintf_s(cmt, sizeof(cmt), SIZESTR(cmt), "%u %s", count, current.c_str());				
				else
					// New comment
					_snprintf_s(cmt, sizeof(cmt), SIZESTR(cmt), "%u", count);

				#if 1
				if (!set_func_cmt(f, cmt, true))
					msg("%llX *** Failed to set function comment! ***\n", f->start_ea);
				#endif
			}
		}
	}
}


// Place a data comment at given address
static void placeDataComment(ea_t address, LPSTR comment)
{
	//msg("%llX '%s'\n", eaAddress, pszComment);
	if(!set_cmt(address, comment, true))
        msg("%llX *** Failed to set data comment! ***\n", address);
}

// Process an item for data references
static void processDataItem(ea_t address)
{
    xrefblk_t xb;
    if (xb.first_to(address, XREF_ALL))
    {
        // Fix for mixed code and data segments
        if (!is_code(get_flags(address)))
        {
            UINT count = 0;
            do
            {
                // Skip the data to data refs
                if ((xb.type > 0) && !((xb.type == dr_O) && !is_code(get_flags(xb.from))))
                    count++;

            } while (xb.next_to());
		
			// If there is more than 1 count
            if (count > 1)
            {
                // Has a comment already?
                BOOL placed = FALSE;
				flags64_t flags = get_flags(address);
                if (has_cmt(flags))
                {
                    // Yes, a repeatable type?					
                    if (get_cmt(NULL, address, TRUE) > 0)
                    {
                        // Don't add count if it's only one
                        if (count > 1)
                        {
							qstring current;
							get_cmt(&current, address, TRUE);

                            char buffer[MAXSTR];
                            _snprintf_s(buffer, sizeof(buffer), SIZESTR(buffer), "%u %s", count, current.c_str());
                            placeDataComment(address, buffer);                            
                        }

                        // Flag we handled it here
                        placed = TRUE;
                    }
                }

                if (!placed)
                {
                    // Is the data a string?
                    if (is_strlit(flags))
                    {
                        //msg("%llX string\n", address);

                        // Don't add count if it's only one
                        if (count > 1)
                        {
                            // Note: This string can be greater then MAXSTR (1024)!
                            int strtype = get_str_type_code(getStringType(address));
                            UINT len = (UINT) get_max_strlit_length(address, strtype, ALOPT_IGNHEADS);
                            if (len > 0)
                            {
								qstring str;
								get_strlit_contents(&str, address, len, strtype, NULL, STRCONV_ESCAPE);

                                char buffer[MAXSTR];
                                int prefixSize = _snprintf_s(buffer, sizeof(buffer), SIZESTR(buffer), "%u \"%s\"", count, str.c_str());
                                placeDataComment(address, buffer);
                            }
                            else
                                msg("%llX *** Get string length failed! ***\n", address);
                        }
                    }
                    else
                        // Add a new comment with just ref count
                    {
                        char buffer[32];
                        _ultoa(count, buffer, 10);
                        placeDataComment(address, buffer);
                    }
                }
            }
        }
    }
}


// ============================================================================
const static char IDAP_name[] = "Mark reference counts";

// Plug-in description block
__declspec(dllexport) plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,	// IDA version plug-in is written for
    PLUGIN_UNL,				// Plug-in flags
    init,					// Initialization function
    term,					// Clean-up function
    run,					// Main plug-in body
    IDAP_name,	            // Comment - unused
    IDAP_name,	            // As above - unused
    IDAP_name,	            // Plug-in name shown in Edit->Plugins menu
    NULL	                // Hot key to run the plug-in
};