#pragma once

// Local (out-of-process) inject / recommend / early-bird — former hdlinjector.
// argv points at the first arg after the "inject" subcommand.
int RunLocalInject(int argc, wchar_t** argv);
void PrintLocalInjectUsage();
